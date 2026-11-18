// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use metrics_util::MetricKind;
use metrics_util::registry::{Registry, Storage};
use opentelemetry::{KeyValue, metrics as otel};

use super::LATENCY_BUCKETS_SECONDS;

type Descriptions = Mutex<HashMap<(MetricKind, KeyName), (SharedString, &'static str)>>;

pub struct OtlpRecorder {
    instruments: Registry<Key, Instruments>,
    descriptions: Arc<Descriptions>,
}

impl OtlpRecorder {
    pub(crate) fn new(meter: otel::Meter) -> Self {
        let descriptions = Arc::new(Descriptions::default());
        let instruments = Registry::new(Instruments {
            meter,
            descriptions: Arc::clone(&descriptions),
        });
        Self {
            instruments,
            descriptions,
        }
    }

    fn describe(&self, kind: MetricKind, name: KeyName, unit: Option<Unit>, text: SharedString) {
        self.descriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((kind, name), (text, unit.map_or("", ucum_unit)));
    }
}

impl Recorder for OtlpRecorder {
    fn describe_counter(&self, name: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe(MetricKind::Counter, name, unit, description);
    }

    fn describe_gauge(&self, name: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe(MetricKind::Gauge, name, unit, description);
    }

    fn describe_histogram(&self, name: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe(MetricKind::Histogram, name, unit, description);
    }

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        self.instruments
            .get_or_create_counter(key, |series| Counter::from_arc(Arc::clone(series)))
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        self.instruments
            .get_or_create_gauge(key, |series| Gauge::from_arc(Arc::clone(series)))
    }

    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        self.instruments
            .get_or_create_histogram(key, |series| Histogram::from_arc(Arc::clone(series)))
    }
}

struct Instruments {
    meter: otel::Meter,
    descriptions: Arc<Descriptions>,
}

impl Instruments {
    fn description(&self, kind: MetricKind, key: &Key) -> (SharedString, &'static str) {
        self.descriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(kind, key.name_shared()))
            .cloned()
            .unwrap_or_default()
    }
}

impl Storage<Key> for Instruments {
    type Counter = Arc<CounterSeries>;
    type Gauge = Arc<GaugeSeries>;
    type Histogram = Arc<HistogramSeries>;

    fn counter(&self, key: &Key) -> Self::Counter {
        let (description, unit) = self.description(MetricKind::Counter, key);
        let instrument = self
            .meter
            .u64_counter(key.name_shared().into_inner())
            .with_description(description)
            .with_unit(unit)
            .build();
        let attributes = attributes(key);
        instrument.add(0, &attributes);
        Arc::new(CounterSeries {
            instrument,
            attributes,
            total: AtomicU64::new(0),
        })
    }

    fn gauge(&self, key: &Key) -> Self::Gauge {
        let (description, unit) = self.description(MetricKind::Gauge, key);
        let instrument = self
            .meter
            .f64_gauge(key.name_shared().into_inner())
            .with_description(description)
            .with_unit(unit)
            .build();
        let attributes = attributes(key);
        instrument.record(0.0, &attributes);
        Arc::new(GaugeSeries {
            instrument,
            attributes,
            value: Mutex::new(0.0),
        })
    }

    fn histogram(&self, key: &Key) -> Self::Histogram {
        let (description, unit) = self.description(MetricKind::Histogram, key);
        let mut builder = self
            .meter
            .f64_histogram(key.name_shared().into_inner())
            .with_description(description)
            .with_unit(unit);
        if key.name().ends_with("_seconds") {
            builder = builder.with_boundaries(LATENCY_BUCKETS_SECONDS.to_vec());
        }
        Arc::new(HistogramSeries {
            instrument: builder.build(),
            attributes: attributes(key),
        })
    }
}

fn attributes(key: &Key) -> Vec<KeyValue> {
    key.labels()
        .map(|label| KeyValue::new(label.key().to_owned(), label.value().to_owned()))
        .collect()
}

fn ucum_unit(unit: Unit) -> &'static str {
    match unit {
        Unit::Count => "1",
        Unit::Microseconds => "us",
        Unit::Bytes => "By",
        Unit::Kibibytes => "KiBy",
        Unit::Mebibytes => "MiBy",
        Unit::Gibibytes => "GiBy",
        Unit::Tebibytes => "TiBy",
        Unit::BitsPerSecond => "bit/s",
        Unit::KilobitsPerSecond => "kbit/s",
        Unit::MegabitsPerSecond => "Mbit/s",
        Unit::GigabitsPerSecond => "Gbit/s",
        Unit::TerabitsPerSecond => "Tbit/s",
        Unit::CountPerSecond => "1/s",
        _ => unit.as_canonical_label(),
    }
}

struct CounterSeries {
    instrument: otel::Counter<u64>,
    attributes: Vec<KeyValue>,
    total: AtomicU64,
}

impl CounterFn for CounterSeries {
    fn increment(&self, value: u64) {
        self.total.fetch_add(value, Ordering::Relaxed);
        self.instrument.add(value, &self.attributes);
    }

    fn absolute(&self, value: u64) {
        let previous = self.total.fetch_max(value, Ordering::Relaxed);
        self.instrument
            .add(value.saturating_sub(previous), &self.attributes);
    }
}

struct GaugeSeries {
    instrument: otel::Gauge<f64>,
    attributes: Vec<KeyValue>,
    value: Mutex<f64>,
}

impl GaugeSeries {
    fn update(&self, change: impl FnOnce(f64) -> f64) {
        // A delayed recording could overwrite a newer sample if it ran outside this lock.
        let mut value = self.value.lock().unwrap_or_else(PoisonError::into_inner);
        *value = change(*value);
        self.instrument.record(*value, &self.attributes);
    }
}

impl GaugeFn for GaugeSeries {
    fn increment(&self, delta: f64) {
        self.update(|value| value + delta);
    }

    fn decrement(&self, delta: f64) {
        self.update(|value| value - delta);
    }

    fn set(&self, value: f64) {
        self.update(|_| value);
    }
}

struct HistogramSeries {
    instrument: otel::Histogram<f64>,
    attributes: Vec<KeyValue>,
}

impl HistogramFn for HistogramSeries {
    fn record(&self, value: f64) {
        self.instrument.record(value, &self.attributes);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{TryLockError, mpsc};
    use std::time::Duration;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    struct PausedMeasurement {
        entered: mpsc::Sender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
    }

    impl otel::SyncInstrument<f64> for PausedMeasurement {
        fn measure(&self, _: f64, _: &[KeyValue]) {
            self.entered.send(()).unwrap();
            self.resume.lock().unwrap().recv_timeout(WAIT).unwrap();
        }
    }

    #[test]
    fn gauge_update_holds_the_lock_during_recording() {
        let (entered, recording) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let gauge = GaugeSeries {
            instrument: otel::Gauge::new(Arc::new(PausedMeasurement {
                entered,
                resume: Mutex::new(resume),
            })),
            attributes: Vec::new(),
            value: Mutex::new(0.0),
        };

        std::thread::scope(|scope| {
            scope.spawn(|| gauge.increment(1.0));
            recording.recv_timeout(WAIT).unwrap();
            let update_blocked = matches!(gauge.value.try_lock(), Err(TryLockError::WouldBlock));
            release.send(()).unwrap();
            assert!(
                update_blocked,
                "another update could overtake this recording"
            );
        });
    }
}
