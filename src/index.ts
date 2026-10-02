// Public exports for @knoxcall/sdk.

export { KnoxCall, Session } from "./client.js";
export { BoundRoute } from "./core.js";
export type { KnoxCallOptions, CallOptions, BoundRouteDefaults } from "./core.js";

export {
  KnoxCallError,
  APIConnectionError,
  APIConnectionTimeoutError,
  APIUserAbortError,
  AuthenticationError,
  PaymentRequiredError,
  PermissionDeniedError,
  PermissionError, // deprecated alias
  NotFoundError,
  ConflictError,
  ValidationError,
  RateLimitError,
  ServerError,
  WebhookSignatureVerificationError,
  SignupError,
  BootstrapError,
  NotAuthenticatedError,
  // AIGW-163: the AI DATA plane's typed refusal. The SDK does not make that
  // call for you (you point a provider SDK at `agent.agent_url`), so the
  // factory is exported alongside the class.
  AIGatewayError,
  aiGatewayErrorFrom,
  isAIGatewayErrorBody,
} from "./error.js";

export { login, ensureLogin } from "./login.js";
export type { LoginOptions } from "./login.js";

export { MemoryTokenStore } from "./auth/token-store.js";
export { FileTokenStore } from "./auth/file-token-store.js";
export { RedisTokenStore } from "./auth/redis-token-store.js";
export type { RedisClient, RedisTokenStoreOptions } from "./auth/redis-token-store.js";
export type { TokenStore, CachedToken } from "./auth/token-store.js";
export type { Bootstrap } from "./auth/bootstrap.js";
export {
  AccessToken,
  ClientCredentials,
  OidcTokenExchange,
  StoredCredentials,
  // Deprecated bootstrap aliases (pre-release names)
  AccessTokenBootstrap,
  ClientCredentialsBootstrap,
  OidcTokenExchangeBootstrap,
} from "./auth/bootstrap.js";
export type { TelemetryHooks, TelemetryRequestInfo, TelemetryResponseInfo, TelemetryRetryInfo } from "./telemetry.js";

// Response envelope + pagination primitives
export type { Envelope, ResponseMeta, Page, PageMeta, PageParams, CursorPage, CursorMeta, CursorParams } from "./resources/shared.js";

// Resource types
export type {
  Route,
  RouteListItem,
  RouteRecord,
  RouteLogEntry,
  RouteEnvironmentSummary,
  RouteEnvironmentConfig,
  RouteAction,
  CreateRouteActionInput,
  ListRoutesResponse,
  CreateRouteInput,
  UpdateRouteInput,
  RouteEnvironmentInput,
} from "./resources/routes.js";
export type {
  Secret,
  SecretType,
  SecretEnvironmentVersion,
  CreateSecretResponse,
  UpdateSecretResponse,
  SecretValueResponse,
  SecretOAuthToken,
  ListSecretsResponse,
  CreateSecretInput,
  UpdateSecretInput,
} from "./resources/secrets.js";
export type {
  Webhook,
  WebhookDetail,
  WebhookHmacFormat,
  CreateWebhookResponse,
  UpdateWebhookResponse,
  WebhookLogEntry,
  WebhookEventType,
  WebhookTestResult,
  CreateWebhookInput,
  UpdateWebhookInput,
  // Typed webhook events (constructEvent)
  KnoxWebhookEvent,
  RequestWebhookEvent,
  AuditWebhookEvent,
  UnknownWebhookEvent,
  RequestWebhookEventType,
  RequestEventData,
  AuditEventData,
  ConstructEventOptions,
} from "./resources/webhooks.js";
export type {
  Client,
  ClientDetail,
  ClientRecord,
  ClientCredential,
  ClientCredentialKind,
  CreateClientCredentialResponse,
  CreateClientInput,
  UpdateClientInput,
} from "./resources/clients.js";
export type {
  OAuthClient,
  OAuthClientDetail,
  CreateOAuthClientResponse,
  RotateOAuthClientSecretResponse,
  CreateOAuthClientInput,
  UpdateOAuthClientInput,
} from "./resources/oauth-clients.js";
export type { Environment, EnvironmentRecord } from "./resources/environments.js";
export type { ApiKey, CreateApiKeyResponse, Role, ListRolesParams } from "./resources/api-keys.js";
export type { Account, AccountUsage, UsageCounter } from "./resources/account.js";
export type { AuditLogEntry, ListAuditLogsParams, AuditEventsParams } from "./resources/audit-logs.js";
export type {
  RequestLog,
  ListRequestLogsParams,
  RequestLogProof,
  ProofStep,
  ProofFailureReason,
} from "./resources/logs.js";
export type { Agent, CreateAgentResponse, AgentTamperEvent } from "./resources/agents.js";
export type {
  CryptoKey,
  CryptoKeySummary,
  InspectResult,
  SealingBundle,
  ClientTokenResponse,
  MintClientTokenInput,
} from "./resources/crypto.js";
export type { CaRoot, CaRole, CreateCaRootResponse, IssueCertResponse } from "./resources/pki.js";
export type {
  Vault,
  VaultDetail,
  Token,
  VaultTokenListItem,
  DetokenizeResponse,
} from "./resources/vaults.js";
export type {
  DbConnection,
  CreateDbConnectionResponse,
  DbRole,
  DbLease,
  DbLeaseList,
  MintDbCredentialResponse,
} from "./resources/dynamic-db.js";

// Standalone helpers
export { verifyWebhookSignature, constructWebhookEvent } from "./resources/webhooks.js";
export { signup, claimSignup } from "./resources/signup.js";
export type {
  SignupInput,
  SignupResponse,
  SignupStarter,
  ClaimSignupInput,
  SignupClaimResponse,
  SignupClaimPending,
  SignupClaimReady,
} from "./resources/signup.js";
export {
  exchangeToken,
  TOKEN_EXCHANGE_GRANT,
  ID_TOKEN_TYPE,
  KNOXCALL_AUDIENCE,
} from "./resources/token-exchange.js";
export type {
  ExchangeTokenInput,
  ExchangeTokenOptions,
  ExchangeTokenResponse,
} from "./resources/token-exchange.js";
// WIF Phase 4.3 — the refreshing counterpart to the one-shot `exchangeToken`,
// for workloads that outlive a single token.
export {
  WorkloadCredentialProvider,
  StaleAssertionError,
  ADVISORY_REFRESH_MS,
  MANDATORY_REFRESH_MS,
} from "./auth/workload-provider.js";
export type {
  WorkloadAssertionSource,
  WorkloadCredentialProviderOptions,
} from "./auth/workload-provider.js";
export type { Workflow, WorkflowExecution, WorkflowRun, CreateWorkflowInput, UpdateWorkflowInput } from "./resources/workflows.js";
export type {
  EscrowWrapCredentialInput,
  EscrowWrapCredentialResponse,
  GatewayUrlInput,
  GatewayUrlResponse,
  WrapGatewayToken,
  InterceptManifest,
  InterceptManifestRoute,
  InterceptManifestOptions,
  WrapFetchOptions,
  WrapCredential,
  RouteAroundRule,
  InterceptEgressOptions,
  InterceptOptions,
  InterceptHandle,
  InterceptHosts,
  HostOptions,
  WrappedFetch,
  EgressInterceptor,
  InterceptDecision,
  InterceptReason,
  InterceptMode,
  ManifestRefreshInfo,
  EgressObservation,
  EgressObservationsReport,
  ReportEgressObservationsOptions,
  ObservationFlushInfo,
} from "./resources/wrap.js";
export { interceptKillSwitch, manifestEtag } from "./resources/wrap.js";
// Uncovered-egress observations (PARITY §21.3): the classifier and the
// reporter, exported so an integrator can drive them by hand.
export {
  EgressObservationReporter,
  credentialHeaderName,
  isCredentialHeaderName,
  observationFirstSegment,
  observationFor,
  firstSegmentLooksLikeCredential,
  observeUncoveredDisabledByEnv,
  CREDENTIAL_HEADER_ALLOWLIST,
  CREDENTIAL_HEADER_SUFFIXES,
} from "./egress-observations.js";
export type { ObservationInput, EgressObservationReporterOptions } from "./egress-observations.js";
export { resolveIntercept, rebasePath as rebaseInterceptPath } from "./intercept-resolver.js";
export { InterceptManifestStore } from "./intercept-manifest-store.js";
export { WrapSandboxMismatchError, DEFAULT_ROUTE_AROUND } from "./resources/wrap.js";
export type {
  Opportunity,
  OpportunitySource,
  OpportunityStatus,
  AcceptOpportunityInput,
  AcceptOpportunityResponse,
  ListOpportunitiesParams,
} from "./resources/opportunities.js";
export type {
  AIGateway,
  CreateGatewayInput,
  UpdateGatewayInput,
  AIAgent,
  CreateAgentInput,
  UpdateAgentInput,
  AIMcpGrant,
  AIMcpServer,
  CreateMcpServerInput,
  UpdateMcpServerInput,
  AIMcpTool,
  UpsertMcpToolInput,
  UpdateMcpToolInput,
  AIGatewayTokenKind,
  AIGatewayTokenListItem,
  MintTokenInput,
  MintTokenResponse,
  UsageParams,
  AIGatewayUsage,
  AIGatewayUsageByModel,
  AIGatewayUsageTotals,
  FirewallRule,
  FirewallPolicy,
  CreateFirewallPolicyInput,
  UpdateFirewallPolicyInput,
  FirewallTestResult,
  PiiAction,
  PiiRecognizerKind,
  PiiPolicy,
  CreatePiiPolicyInput,
  UpdatePiiPolicyInput,
  PiiRecognizer,
  CreatePiiRecognizerInput,
  UpdatePiiRecognizerInput,
  PiiRecognizerTestResult,
} from "./resources/ai-gateway.js";
