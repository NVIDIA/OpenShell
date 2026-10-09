// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{PersistenceResult, Store, WriteCondition, WriteResult};
use openshell_core::proto::Sandbox;

/// A physical target and the exact logical attempt entitled to claim it.
/// Reservations have no TTL: an uncertain driver call may still be in flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationClaim {
    pub target: String,
    pub sandbox_id: String,
    pub attempt_id: String,
    pub runtime_generation: String,
}

impl Store {
    pub(crate) async fn allocation_conflicts(
        &self,
        claim: &AllocationClaim,
    ) -> PersistenceResult<bool> {
        match self {
            Self::Sqlite(store) => store.allocation_conflicts(claim).await,
            Self::Postgres(store) => store.allocation_conflicts(claim).await,
        }
    }
    /// Commit sandbox intent and exclusive target ownership in one transaction.
    /// Any target or sandbox CAS conflict rolls back both writes.
    #[tracing::instrument(name = "store", skip_all, fields(otel.name = "store.put_sandbox_allocation", otel.status_code = tracing::field::Empty))]
    pub(crate) async fn put_sandbox_allocation(
        &self,
        sandbox: &Sandbox,
        claim: Option<&AllocationClaim>,
        condition: WriteCondition,
    ) -> PersistenceResult<WriteResult> {
        use openshell_core::ObjectId;
        if claim.is_some_and(|claim| claim.sandbox_id != sandbox.object_id()) {
            return Err(super::PersistenceError::Config(
                "allocation owner must match sandbox".into(),
            ));
        }
        let result = match self {
            Self::Sqlite(store) => {
                store
                    .put_sandbox_allocation(sandbox, claim, condition)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .put_sandbox_allocation(sandbox, claim, condition)
                    .await
            }
        };
        if let Err(error) = &result
            && !error.is_expected()
        {
            crate::otel_tracing::mark_error(&tracing::Span::current());
        }
        result
    }

    /// Only call after the driver has fenced or reclaimed this owner's target.
    pub(crate) async fn release_allocation(
        &self,
        claim: &AllocationClaim,
    ) -> PersistenceResult<()> {
        match self {
            Self::Sqlite(store) => store.release_allocation(claim).await,
            Self::Postgres(store) => store.release_allocation(claim).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::PersistenceError;
    use openshell_core::{ObjectId, proto::ObjectMeta};

    fn intent(id: &str, target: &str) -> (Sandbox, AllocationClaim) {
        let sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: id.into(),
                name: id.into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let claim = AllocationClaim {
            target: target.into(),
            sandbox_id: id.into(),
            attempt_id: "attempt".into(),
            runtime_generation: "generation".into(),
        };
        (sandbox, claim)
    }

    async fn check_atomic_reservations(store: &Store) {
        let prefix = uuid::Uuid::new_v4().to_string();
        let (first, owner) = intent(&format!("{prefix}-first"), &format!("{prefix}-target"));
        let (second, contender) = intent(&format!("{prefix}-second"), &owner.target);
        let inserted = store
            .put_sandbox_allocation(&first, Some(&owner), WriteCondition::MustCreate)
            .await
            .unwrap();
        assert!(matches!(
            store
                .put_sandbox_allocation(&second, Some(&contender), WriteCondition::MustCreate)
                .await,
            Err(PersistenceError::AllocationTargetReserved)
        ));
        assert!(
            store
                .get_message::<Sandbox>(second.object_id())
                .await
                .unwrap()
                .is_none(),
            "losing create must roll back its sandbox row"
        );

        let updated = store
            .put_sandbox_allocation(
                &first,
                Some(&owner),
                WriteCondition::MatchResourceVersion(inserted.resource_version),
            )
            .await
            .unwrap();
        let mut wrong_attempt = owner.clone();
        wrong_attempt.attempt_id = "new-attempt".into();
        assert!(matches!(
            store
                .put_sandbox_allocation(
                    &first,
                    Some(&wrong_attempt),
                    WriteCondition::MatchResourceVersion(updated.resource_version)
                )
                .await,
            Err(PersistenceError::AllocationTargetReserved)
        ));
        let current = store
            .get_message::<Sandbox>(first.object_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.metadata.as_ref().unwrap().resource_version,
            updated.resource_version,
            "failed reservation must roll back the sandbox update"
        );
        store.release_allocation(&wrong_attempt).await.unwrap();
        assert!(
            store.allocation_conflicts(&contender).await.unwrap(),
            "a stale attempt cannot release ownership"
        );

        let mut unused = owner.clone();
        unused.target = format!("{prefix}-unused");
        assert!(matches!(
            store
                .put_sandbox_allocation(
                    &first,
                    Some(&unused),
                    WriteCondition::MatchResourceVersion(inserted.resource_version)
                )
                .await,
            Err(PersistenceError::Conflict { .. })
        ));
        unused.sandbox_id.clone_from(&contender.sandbox_id);
        assert!(
            !store.allocation_conflicts(&unused).await.unwrap(),
            "failed sandbox CAS cannot reserve a target"
        );

        store.release_allocation(&owner).await.unwrap();
        store
            .put_sandbox_allocation(&second, Some(&contender), WriteCondition::MustCreate)
            .await
            .unwrap();
        store.delete("sandbox", second.object_id()).await.unwrap();
        assert!(
            !store.allocation_conflicts(&owner).await.unwrap(),
            "logical deletion must remove its reservation"
        );
        store.delete("sandbox", first.object_id()).await.unwrap();
    }

    #[tokio::test]
    async fn allocation_reservations_are_atomic_and_owner_fenced() {
        check_atomic_reservations(&crate::persistence::test_store().await).await;
    }

    #[tokio::test]
    async fn allocation_reservation_has_one_winner_across_connections_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("allocation.db").display());
        let left = Store::connect(&url).await.unwrap();
        let right = Store::connect(&url).await.unwrap();
        let (first, owner) = intent("first", "same-target");
        let (second, contender) = intent("second", "same-target");
        let (a, b) = tokio::join!(
            left.put_sandbox_allocation(&first, Some(&owner), WriteCondition::MustCreate),
            right.put_sandbox_allocation(&second, Some(&contender), WriteCondition::MustCreate),
        );
        assert_ne!(a.is_ok(), b.is_ok());
        let losing_claim = if a.is_ok() { &contender } else { &owner };
        assert!(matches!(
            if a.is_ok() { b } else { a },
            Err(PersistenceError::AllocationTargetReserved)
        ));
        left.close_for_test().await;
        right.close_for_test().await;
        let restarted = Store::connect(&url).await.unwrap();
        assert!(restarted.allocation_conflicts(losing_claim).await.unwrap());
        assert!(
            restarted
                .get_message::<Sandbox>(&losing_claim.sandbox_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[ignore = "requires OPENSHELL_TEST_POSTGRES_URL pointing to a disposable PostgreSQL database"]
    async fn allocation_reservations_postgres() {
        let url = std::env::var("OPENSHELL_TEST_POSTGRES_URL").unwrap();
        let left = Store::connect(&url).await.unwrap();
        check_atomic_reservations(&left).await;
        let right = Store::connect(&url).await.unwrap();
        let target = uuid::Uuid::new_v4().to_string();
        let (first, owner) = intent(&format!("{target}-left"), &target);
        let (second, contender) = intent(&format!("{target}-right"), &target);
        let (a, b) = tokio::join!(
            left.put_sandbox_allocation(&first, Some(&owner), WriteCondition::MustCreate),
            right.put_sandbox_allocation(&second, Some(&contender), WriteCondition::MustCreate),
        );
        assert_ne!(a.is_ok(), b.is_ok());
        let losing_claim = if a.is_ok() { &contender } else { &owner };
        assert!(matches!(
            if a.is_ok() { b } else { a },
            Err(PersistenceError::AllocationTargetReserved)
        ));
        let restarted = Store::connect(&url).await.unwrap();
        assert!(restarted.allocation_conflicts(losing_claim).await.unwrap());
        assert!(
            restarted
                .get_message::<Sandbox>(&losing_claim.sandbox_id)
                .await
                .unwrap()
                .is_none()
        );
        left.delete("sandbox", first.object_id()).await.unwrap();
        left.delete("sandbox", second.object_id()).await.unwrap();
    }
}
