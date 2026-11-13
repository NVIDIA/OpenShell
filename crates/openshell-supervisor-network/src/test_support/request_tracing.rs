// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use openshell_ocsf::test_support::OcsfCapture;
use opentelemetry_sdk::trace::{InMemorySpanExporter, Sampler, SdkTracerProvider, SpanData};
use tracing_subscriber::{layer::SubscriberExt as _, registry::LookupSpan};

#[derive(Clone, Default)]
struct CreatedSpans(Arc<Mutex<Vec<&'static str>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CreatedSpans {
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _id: &tracing::Id,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.0.lock().unwrap().push(attributes.metadata().name());
    }
}

pub struct RequestTracing {
    pub events: OcsfCapture,
    exporter: InMemorySpanExporter,
    provider: Option<SdkTracerProvider>,
    created: CreatedSpans,
}

impl RequestTracing {
    pub fn new(sampler: Option<Sampler>) -> Self {
        crate::telemetry::tests::init_trace_extractor();
        let exporter = InMemorySpanExporter::default();
        let provider = sampler.map(|sampler| {
            SdkTracerProvider::builder()
                .with_sampler(sampler)
                .with_simple_exporter(exporter.clone())
                .build()
        });
        Self {
            events: OcsfCapture::default(),
            exporter,
            provider,
            created: CreatedSpans::default(),
        }
    }

    pub fn subscriber(
        &self,
    ) -> impl tracing::Subscriber + for<'span> LookupSpan<'span> + Send + Sync + 'static {
        let layer = self
            .provider
            .as_ref()
            .map(|provider| openshell_otel::layer(provider, "request-test"));
        tracing_subscriber::registry()
            .with(self.events.clone())
            .with(self.created.clone())
            .with(layer)
    }

    pub fn spans(&self) -> Vec<SpanData> {
        if let Some(provider) = &self.provider {
            provider.force_flush().unwrap();
        }
        self.exporter.get_finished_spans().unwrap()
    }

    pub fn created_span_names(&self) -> Vec<&'static str> {
        self.created.0.lock().unwrap().clone()
    }

    pub fn shutdown(&self) {
        if let Some(provider) = &self.provider {
            provider.shutdown().unwrap();
        }
    }
}
