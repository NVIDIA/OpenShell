// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP/gRPC metric export, and a `metrics` recorder that feeds it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use metrics_util::registry::{Registry, Storage};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;
use opentelemetry_otlp::MetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

use crate::{OtlpTarget, SetupError};

impl OtlpTarget {
    /// Build a meter provider that exports metrics to this target on the
    /// SDK's periodic interval (`OTEL_METRIC_EXPORT_INTERVAL`).
    pub fn meter_provider(&self) -> Result<SdkMeterProvider, SetupError> {
        let exporter = self
            .configure(MetricExporter::builder().with_tonic())
            .build()?;
        Ok(SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter).build())
            .with_resource(self.resource().clone())
            .build())
    }
}

type Descriptions = Mutex<HashMap<KeyName, (Option<Unit>, SharedString)>>;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A `metrics` recorder that records into OpenTelemetry instruments.
///
/// Install it next to another recorder with `metrics_util::layers::FanoutBuilder`.
/// A counter only grows, so `absolute` below the current total is ignored.
/// A gauge exports its last value. Every histogram uses `histogram_boundaries`.
/// Descriptions apply to series registered after they are described.
pub struct MetricsBridge {
    registry: Registry<Key, Instruments>,
    descriptions: Arc<Descriptions>,
}

impl MetricsBridge {
    #[must_use]
    pub fn new(meter: Meter, histogram_boundaries: Vec<f64>) -> Self {
        let descriptions = Arc::new(Descriptions::default());
        let storage = Instruments {
            meter,
            histogram_boundaries,
            descriptions: descriptions.clone(),
        };
        Self {
            registry: Registry::new(storage),
            descriptions,
        }
    }

    fn describe(&self, name: KeyName, unit: Option<Unit>, description: SharedString) {
        lock(&self.descriptions).insert(name, (unit, description));
    }
}

impl Recorder for MetricsBridge {
    fn describe_counter(&self, name: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe(name, unit, description);
    }

    fn describe_gauge(&self, name: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe(name, unit, description);
    }

    fn describe_histogram(&self, name: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe(name, unit, description);
    }

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        self.registry
            .get_or_create_counter(key, |counter| Counter::from_arc(counter.clone()))
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        self.registry
            .get_or_create_gauge(key, |gauge| Gauge::from_arc(gauge.clone()))
    }

    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        self.registry
            .get_or_create_histogram(key, |histogram| Histogram::from_arc(histogram.clone()))
    }
}

/// Builds the instrument behind each new series.
struct Instruments {
    meter: Meter,
    histogram_boundaries: Vec<f64>,
    descriptions: Arc<Descriptions>,
}

impl Instruments {
    /// The OpenTelemetry description and UCUM unit, empty when never described.
    fn metadata(&self, key: &Key) -> (SharedString, &'static str) {
        lock(&self.descriptions)
            .get(key.name())
            .map_or_else(Default::default, |(unit, description)| {
                (description.clone(), unit.map_or("", ucum))
            })
    }
}

fn ucum(unit: Unit) -> &'static str {
    match unit {
        Unit::Count => "1",
        Unit::Seconds => "s",
        Unit::Bytes => "By",
        other => other.as_canonical_label(),
    }
}

fn attributes(key: &Key) -> Vec<KeyValue> {
    key.labels()
        .map(|label| KeyValue::new(label.key().to_owned(), label.value().to_owned()))
        .collect()
}

impl Storage<Key> for Instruments {
    type Counter = Arc<OtelCounter>;
    type Gauge = Arc<OtelGauge>;
    type Histogram = Arc<OtelHistogram>;

    fn counter(&self, key: &Key) -> Self::Counter {
        let (description, unit) = self.metadata(key);
        Arc::new(OtelCounter {
            counter: self
                .meter
                .u64_counter(key.name_shared().into_inner())
                .with_description(description)
                .with_unit(unit)
                .build(),
            attributes: attributes(key),
            total: AtomicU64::new(0),
        })
    }

    fn gauge(&self, key: &Key) -> Self::Gauge {
        let (description, unit) = self.metadata(key);
        Arc::new(OtelGauge {
            gauge: self
                .meter
                .f64_gauge(key.name_shared().into_inner())
                .with_description(description)
                .with_unit(unit)
                .build(),
            attributes: attributes(key),
            value: Mutex::new(0.0),
        })
    }

    fn histogram(&self, key: &Key) -> Self::Histogram {
        let (description, unit) = self.metadata(key);
        Arc::new(OtelHistogram {
            histogram: self
                .meter
                .f64_histogram(key.name_shared().into_inner())
                .with_description(description)
                .with_unit(unit)
                .with_boundaries(self.histogram_boundaries.clone())
                .build(),
            attributes: attributes(key),
        })
    }
}

struct OtelCounter {
    counter: opentelemetry::metrics::Counter<u64>,
    attributes: Vec<KeyValue>,
    total: AtomicU64,
}

impl CounterFn for OtelCounter {
    fn increment(&self, value: u64) {
        self.total.fetch_add(value, Ordering::Relaxed);
        self.counter.add(value, &self.attributes);
    }

    fn absolute(&self, value: u64) {
        let previous = self.total.fetch_max(value, Ordering::Relaxed);
        self.counter
            .add(value.saturating_sub(previous), &self.attributes);
    }
}

/// Keeps the value here because the metrics API adjusts gauges by a delta and
/// OpenTelemetry records the new value. The lock orders concurrent updates so
/// the last recorded value is the current one.
struct OtelGauge {
    gauge: opentelemetry::metrics::Gauge<f64>,
    attributes: Vec<KeyValue>,
    value: Mutex<f64>,
}

impl OtelGauge {
    fn update(&self, change: impl FnOnce(f64) -> f64) {
        let mut value = lock(&self.value);
        *value = change(*value);
        self.gauge.record(*value, &self.attributes);
    }
}

impl GaugeFn for OtelGauge {
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

struct OtelHistogram {
    histogram: opentelemetry::metrics::Histogram<f64>,
    attributes: Vec<KeyValue>,
}

impl HistogramFn for OtelHistogram {
    fn record(&self, value: f64) {
        self.histogram.record(value, &self.attributes);
    }
}

#[cfg(test)]
mod tests {
    use metrics::{counter, describe_counter, describe_histogram, gauge, histogram};
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::data::{
        AggregatedMetrics, GaugeDataPoint, MetricData, ResourceMetrics, ScopeMetrics, SumDataPoint,
    };
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader};

    use super::*;
    use crate::{OtlpExportConfig, ServiceName};

    fn bridge() -> (MetricsBridge, SdkMeterProvider, InMemoryMetricExporter) {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        let bridge = MetricsBridge::new(provider.meter("test"), vec![0.1, 1.0]);
        (bridge, provider, exporter)
    }

    fn flushed(provider: &SdkMeterProvider, exporter: &InMemoryMetricExporter) -> ResourceMetrics {
        provider.force_flush().expect("flush");
        exporter
            .get_finished_metrics()
            .expect("metrics")
            .pop()
            .expect("an export")
    }

    fn metric<'a>(
        metrics: &'a ResourceMetrics,
        name: &str,
    ) -> &'a opentelemetry_sdk::metrics::data::Metric {
        metrics
            .scope_metrics()
            .flat_map(ScopeMetrics::metrics)
            .find(|metric| metric.name() == name)
            .unwrap_or_else(|| panic!("{name} was not exported"))
    }

    #[test]
    fn counters_sum_per_label_set_and_never_decrease() {
        let (bridge, provider, exporter) = bridge();
        metrics::with_local_recorder(&bridge, || {
            counter!("hits_total", "route" => "a").increment(2);
            counter!("hits_total", "route" => "a").increment(3);
            counter!("hits_total", "route" => "b").absolute(7);
            counter!("hits_total", "route" => "b").absolute(4);
            counter!("zero_total").increment(0);
        });
        let data = flushed(&provider, &exporter);

        let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric(&data, "hits_total").data()
        else {
            panic!("hits_total is not a u64 sum");
        };
        let mut points: Vec<_> = sum
            .data_points()
            .map(|point| {
                let route = point.attributes().next().expect("route").value.to_string();
                (route, point.value())
            })
            .collect();
        points.sort();
        assert_eq!(points, [("a".to_string(), 5), ("b".to_string(), 7)]);

        let AggregatedMetrics::U64(MetricData::Sum(zero)) = metric(&data, "zero_total").data()
        else {
            panic!("zero_total is not a u64 sum");
        };
        assert_eq!(
            zero.data_points()
                .map(SumDataPoint::value)
                .collect::<Vec<_>>(),
            [0]
        );
    }

    #[test]
    fn gauges_export_their_last_value_across_handles() {
        let (bridge, provider, exporter) = bridge();
        metrics::with_local_recorder(&bridge, || {
            let first = gauge!("sessions");
            first.increment(3.0);
            gauge!("sessions").decrement(1.0);
            first.increment(0.5);
            gauge!("capacity").set(8.0);
            gauge!("capacity").set(9.0);
        });
        let data = flushed(&provider, &exporter);

        for (name, expected) in [("sessions", 2.5), ("capacity", 9.0)] {
            let AggregatedMetrics::F64(MetricData::Gauge(gauge)) = metric(&data, name).data()
            else {
                panic!("{name} is not an f64 gauge");
            };
            let values: Vec<_> = gauge.data_points().map(GaugeDataPoint::value).collect();
            assert_eq!(values, [expected], "{name}");
        }
    }

    #[test]
    fn histograms_use_the_configured_boundaries() {
        let (bridge, provider, exporter) = bridge();
        metrics::with_local_recorder(&bridge, || {
            let latency = histogram!("latency_seconds", "op" => "x");
            latency.record(0.05);
            latency.record(0.5);
            latency.record(30.0);
        });
        let data = flushed(&provider, &exporter);

        let AggregatedMetrics::F64(MetricData::Histogram(histogram)) =
            metric(&data, "latency_seconds").data()
        else {
            panic!("latency_seconds is not an f64 histogram");
        };
        let point = histogram.data_points().next().expect("a data point");
        assert_eq!(point.count(), 3);
        assert_eq!(point.bounds().collect::<Vec<_>>(), [0.1, 1.0]);
        assert_eq!(point.bucket_counts().collect::<Vec<_>>(), [1, 1, 1]);
    }

    #[test]
    fn descriptions_and_units_reach_the_instrument() {
        let (bridge, provider, exporter) = bridge();
        metrics::with_local_recorder(&bridge, || {
            describe_counter!("described_total", Unit::Count, "Things that happened.");
            describe_histogram!("described_seconds", Unit::Seconds, "How long it took.");
            counter!("described_total").increment(1);
            histogram!("described_seconds").record(0.2);
            counter!("undescribed_total").increment(1);
        });
        let data = flushed(&provider, &exporter);

        let counter = metric(&data, "described_total");
        assert_eq!(counter.description(), "Things that happened.");
        assert_eq!(counter.unit(), "1");
        let histogram = metric(&data, "described_seconds");
        assert_eq!(histogram.description(), "How long it took.");
        assert_eq!(histogram.unit(), "s");
        assert_eq!(metric(&data, "undescribed_total").unit(), "");
    }

    #[tokio::test]
    async fn target_builds_a_meter_provider_with_its_resource() {
        let target = OtlpTarget::new(&OtlpExportConfig {
            endpoint: "http://127.0.0.1:4317",
            service_name: ServiceName::Fixed("openshell-gateway"),
            service_version: None,
            resource_attributes: Vec::new(),
        })
        .unwrap();
        target.meter_provider().expect("meter provider");
    }
}
