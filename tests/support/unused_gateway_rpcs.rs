// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unused unary methods shared by mock OpenShell gateways.

#[macro_export]
macro_rules! unused_gateway_rpcs {
    (sandbox_templates) => {
        $crate::unused_gateway_rpcs! {
            create_sandbox_template(CreateSandboxTemplateRequest) -> SandboxTemplateResponse;
            get_sandbox_template(GetSandboxTemplateRequest) -> SandboxTemplateResponse;
            list_sandbox_templates(ListSandboxTemplatesRequest) -> ListSandboxTemplatesResponse;
            delete_sandbox_template(DeleteSandboxTemplateRequest) -> DeleteSandboxTemplateResponse;
        }
    };
    (provider_token_grants) => {
        $crate::unused_gateway_rpcs! {
            mint_provider_client_assertion(MintProviderClientAssertionRequest) -> MintProviderClientAssertionResponse;
            exchange_provider_subject_token(ExchangeProviderSubjectTokenRequest) -> ExchangeProviderSubjectTokenResponse;
        }
    };
    // async_trait expands the impl before this macro, so emit its boxed signature.
    ($( $method:ident($request:ident) -> $response:ident; )+) => {
        $(fn $method<'life0, 'async_trait>(
            &'life0 self,
            _: tonic::Request<openshell_core::proto::$request>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<
            Output = Result<tonic::Response<openshell_core::proto::$response>, tonic::Status>,
        > + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(tonic::Status::unimplemented("unused")) })
        })+
    };
}
