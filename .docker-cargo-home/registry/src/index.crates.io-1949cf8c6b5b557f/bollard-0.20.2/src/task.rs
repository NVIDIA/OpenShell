//! Tasks API: A task is a container running on a swarm. It is the atomic scheduling unit of swarm. Swarm mode must be enabled for these endpoints to work.

use bollard_stubs::models::Task;
use bytes::Bytes;
use futures_core::Stream;
use http_body_util::Full;

use crate::{container::LogOutput, docker::BodyType, errors::Error, Docker};
use http::{request::Builder, Method};

impl Docker {
    /// ---
    ///
    /// # List Tasks
    ///
    /// # Arguments
    ///
    ///  - Optional [List Tasks Options](crate::query_parameters::ListTasksOptions) struct.
    ///
    /// # Returns
    ///
    ///  - A vector of [Task](Task) struct, wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// use bollard::query_parameters::ListTasksOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("label", vec!["my-task-label"]);
    ///
    /// let options = ListTasksOptionsBuilder::default()
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.list_tasks(Some(options));
    /// ```
    pub async fn list_tasks(
        &self,
        options: Option<crate::query_parameters::ListTasksOptions>,
    ) -> Result<Vec<Task>, Error> {
        let url = "/tasks";

        let req = self.build_request(
            url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Inspect a Task
    ///
    /// # Arguments
    ///
    ///  - Task id as a string slice.
    ///
    /// # Returns
    ///
    ///  - A [Models](Task) struct, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.inspect_task("my_task_id");
    /// ```
    pub async fn inspect_task(&self, task_id: &str) -> Result<Task, Error> {
        let url = format!("/tasks/{task_id}");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Get Task Logs
    ///
    /// Get `stdout` and `stderr` logs from a task.
    ///
    /// # Arguments
    ///
    ///  - Task id as a string slice.
    ///  - Optional [Logs Options](crate::query_parameters::LogsOptions) struct.
    ///
    /// # Returns
    ///
    ///  - A Stream of [Log Output](LogOutput) results.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::LogsOptionsBuilder;
    ///
    /// let options = LogsOptionsBuilder::default()
    ///     .stdout(true)
    ///     .build();
    ///
    /// docker.task_logs("my-task-id", Some(options));
    /// ```
    pub fn task_logs(
        &self,
        task_id: &str,
        options: Option<impl Into<crate::query_parameters::LogsOptions>>,
    ) -> impl Stream<Item = Result<LogOutput, Error>> {
        let url = format!("/tasks/{task_id}/logs");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            options.map(Into::into),
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_stream_string(req)
    }
}
