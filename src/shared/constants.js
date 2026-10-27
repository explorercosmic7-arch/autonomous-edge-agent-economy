/**
 * Shared configuration constants for Autonomous Edge-Agent Economy.
 * Rate limits, system accounts, TTL bounds, safety/credit/shield defaults.
 */

export const DASHBOARD_URL = "https://edgerail.pages.dev/ai-agents-payment-gateway";
export const SESSION_DAYS = 14;

export const FAUCET_MAX_PER_CALL = 10;
export const FAUCET_ACCOUNT_CAP = 100;
export const SYSTEM_FAUCET = "system/faucet";
export const SYSTEM_ESCROW = "system/escrow";
export const MAX_KEYS_PER_USER = 10;

export const RL_KEY_CREATE_MAX = 3;
export const RL_KEY_CREATE_WINDOW_SEC = 3600;
export const RL_PAY_MAX = 60;
export const RL_PAY_WINDOW_SEC = 60;
export const RL_ESCROW_MAX = 30;
export const RL_ESCROW_WINDOW_SEC = 60;

export const ESCROW_DEFAULT_TTL_HOURS = 72;
export const ESCROW_MIN_TTL_SEC = 10;
export const ESCROW_MAX_TTL_SEC = 720 * 3600;
export const EXPIRE_BATCH_LIMIT = 50;
export const WEBHOOK_TIMEOUT_MS = 5000;
export const RL_WEBHOOK_SET_MAX = 10;
export const RL_WEBHOOK_SET_WINDOW_SEC = 3600;
export const RL_GITHUB_REPOS_MAX = 12;
export const RL_GITHUB_REPOS_WINDOW_SEC = 3600;
export const RL_STREAM_MAX = 30;
export const RL_STREAM_WINDOW_SEC = 60;
export const SYSTEM_STREAM = "system/stream";
export const STREAM_MIN_BUDGET = 0.000001;
export const STREAM_MAX_BUDGET = 10000;

export const SYSTEM_SUBWALLET = "system/subwallet";
export const SUBWALLET_MIN_BUDGET = 0.000001;
export const SUBWALLET_MAX_BUDGET = 10000;
export const SUBWALLET_DEFAULT_TTL_SEC = 3600; // 1h
export const SUBWALLET_MIN_TTL_SEC = 30;
export const SUBWALLET_MAX_TTL_SEC = 72 * 3600; // 72h
export const RL_SUBWALLET_MAX = 40;
export const RL_SUBWALLET_WINDOW_SEC = 60;
export const EXPIRE_SUBWALLET_BATCH = 50;

export const SYSTEM_NETTING = "system/netting";
export const NETTING_DEFAULT_WINDOW_HOURS = 24;
export const NETTING_MIN_WINDOW_HOURS = 1;
export const NETTING_MAX_WINDOW_HOURS = 168;
export const NETTING_MAX_PAIRS = 200;
export const RL_NETTING_MAX = 5;
export const RL_NETTING_WINDOW_SEC = 3600;

export const SYSTEM_TICKET = "system/ticket";
export const TICKET_MIN_UNITS = 0.000001;
export const TICKET_MAX_UNITS = 1_000_000;
export const TICKET_DEFAULT_TTL_SEC = 3600;
export const TICKET_MIN_TTL_SEC = 30;
export const TICKET_MAX_TTL_SEC = 72 * 3600;
export const RL_TICKET_MAX = 40;
export const RL_TICKET_WINDOW_SEC = 60;
export const EXPIRE_TICKET_BATCH = 50;

export const SYSTEM_BOND = "system/bond";
export const SYSTEM_SLASH_POOL = "system/slash-pool";
export const BOND_MIN = 0.000001;
export const BOND_MAX = 10000;
export const BOND_DEFAULT_TTL_SEC = 3600;
export const BOND_MIN_TTL_SEC = 30;
export const BOND_MAX_TTL_SEC = 72 * 3600;
export const BOND_DEFAULT_MATCH_TTL_SEC = 1800;
export const BOND_DEFAULT_SLASH_BPS = 5000; // 50% on full slash default
export const RL_BOND_MAX = 30;
export const RL_BOND_WINDOW_SEC = 60;
export const EXPIRE_BOND_BATCH = 50;

export const SYSTEM_SAGA = "system/saga";
export const SAGA_MIN_BUDGET = 0.000001;
export const SAGA_MAX_BUDGET = 100000;
export const SAGA_MAX_STEPS = 20;
export const SAGA_DEFAULT_TTL_SEC = 7200;
export const SAGA_MIN_TTL_SEC = 60;
export const SAGA_MAX_TTL_SEC = 72 * 3600;
export const RL_SAGA_MAX = 20;
export const RL_SAGA_WINDOW_SEC = 60;
export const EXPIRE_SAGA_BATCH = 30;


/* Safety defaults (override per-repo via agent_limits) */
export const SAFETY_DEFAULT_VELOCITY_MAX_TX = 50;       // max txs in window
export const SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC = 5;
export const SAFETY_DEFAULT_VELOCITY_MAX_USD = 2.0;     // max spend in window
export const SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC = 60;
export const SAFETY_SPIKE_TX_PER_SEC = 100;             // instant spike threshold
export const SAFETY_VELOCITY_PRUNE_HOURS = 24;

/* Reputation-backed credit */
export const CREDIT_DEFAULT_LIMIT = 0;           // no credit unless set or earned
export const CREDIT_MAX_LIMIT = 10000;
export const CREDIT_REP_PER_USD = 10;            // +10 rep per $1 successful spend (capped)
export const CREDIT_REP_SUCCESS_BONUS = 1;       // flat +1 on successful pay/escrow release
export const CREDIT_REP_FAIL_PENALTY = 5;        // -5 on slash / compensate / lock
export const CREDIT_REP_TO_LIMIT_RATIO = 0.01;   // credit_limit ≈ rep_score * 0.01 (e.g. 1000 rep → $10)
export const CREDIT_AUTO_LIMIT = true;           // auto-raise suggested limit from rep (never above explicit set if locked)
export const RL_CREDIT_MAX = 20;
export const RL_CREDIT_WINDOW_SEC = 60;

/* Commit–reveal counterfactual pay */
export const SYSTEM_COMMIT = "system/commit";
export const COMMIT_MIN = 0.000001;
export const COMMIT_MAX = 100000;
export const COMMIT_DEFAULT_TTL_SEC = 3600;
export const COMMIT_MIN_TTL_SEC = 30;
export const COMMIT_MAX_TTL_SEC = 72 * 3600;
export const RL_COMMIT_MAX = 40;
export const RL_COMMIT_WINDOW_SEC = 60;
export const EXPIRE_COMMIT_BATCH = 50;

/* Cross-deployment clearing */
export const SYSTEM_CLEARING = "system/clearing";
export const CLEARING_DEFAULT_WINDOW_HOURS = 24;
export const CLEARING_MIN_WINDOW_HOURS = 1;
export const CLEARING_MAX_WINDOW_HOURS = 168;
export const CLEARING_MAX_REPOS = 500;
export const RL_CLEARING_MAX = 8;
export const RL_CLEARING_WINDOW_SEC = 3600;

/* Verifiable Work Settlement */
export const SYSTEM_WORK = "system/work";
export const WORK_MIN = 0.000001;
export const WORK_MAX = 100000;
export const WORK_DEFAULT_TTL_SEC = 3600;
export const WORK_MIN_TTL_SEC = 30;
export const WORK_MAX_TTL_SEC = 72 * 3600;
export const RL_WORK_MAX = 40;
export const RL_WORK_WINDOW_SEC = 60;
export const EXPIRE_WORK_BATCH = 50;

/* Attestation diversity (VWS) */
export const WORK_BLOCK_SELF_ATTEST = true; // provider + buyer cannot attest own claim
export const WORK_REQUIRE_DISTINCT_ATTESTORS = true; // one vote per attestor_repo per claim


/* Heartbeat Continuity (dead-agent recovery) */
export const SYSTEM_CONTINUITY = "system/continuity";
export const CONT_MIN_BOND = 0;
export const CONT_MAX_BOND = 100000;
export const CONT_DEFAULT_INTERVAL_SEC = 120;
export const CONT_MIN_INTERVAL_SEC = 15;
export const CONT_MAX_INTERVAL_SEC = 24 * 3600;
export const CONT_DEFAULT_GRACE_SEC = 30;
export const CONT_MIN_GRACE_SEC = 0;
export const CONT_MAX_GRACE_SEC = 3600;
export const CONT_DEFAULT_MISS_LIMIT = 1;
export const CONT_MAX_MISS_LIMIT = 10;
export const RL_CONT_MAX = 60;
export const RL_CONT_WINDOW_SEC = 60;
export const EXPIRE_CONT_BATCH = 50;

/* Collaborative Pools (swarm co-funding) */
export const SYSTEM_POOL = "system/pool";
export const POOL_MIN = 0.000001;
export const POOL_MAX = 100000;
export const POOL_DEFAULT_TTL_SEC = 72 * 3600;
export const POOL_MIN_TTL_SEC = 60;
export const POOL_MAX_TTL_SEC = 720 * 3600;
export const RL_POOL_MAX = 30;
export const RL_POOL_WINDOW_SEC = 60;
export const EXPIRE_POOL_BATCH = 40;

/* Edge Shield — adaptive circuit breaker / quarantine */
export const SHIELD_LEVEL_NORMAL = 0;
export const SHIELD_LEVEL_WATCH = 1;      // log + tighter soft limits
export const SHIELD_LEVEL_THROTTLE = 2;   // cut rate limits in half
export const SHIELD_LEVEL_FREEZE = 3;     // block new spends (refunds/settles OK)
export const SHIELD_LEVEL_EMERGENCY = 4;  // global freeze all discretionary spends
export const SHIELD_AUTO_LOCKS_TRIP = 3;  // N wallet locks in window → global escalate
export const SHIELD_AUTO_WINDOW_SEC = 300;
export const SHIELD_COOLDOWN_SEC = 600;   // default auto cool-down
export const SHIELD_MAX_LEVEL = 4;
export const RL_SHIELD_MAX = 30;
export const RL_SHIELD_WINDOW_SEC = 60;

/* Spend Intent Capsules */
export const SYSTEM_INTENT = "system/intent";
export const INTENT_MIN = 0.000001;
export const INTENT_MAX = 100000;
export const INTENT_DEFAULT_TTL_SEC = 3600;
export const INTENT_MIN_TTL_SEC = 30;
export const INTENT_MAX_TTL_SEC = 72 * 3600;
export const RL_INTENT_MAX = 40;
export const RL_INTENT_WINDOW_SEC = 60;
export const EXPIRE_INTENT_BATCH = 50;

/* Hire Protocol */
export const SYSTEM_HIRE = "system/hire";
export const HIRE_MIN = 0.000001;
export const HIRE_MAX = 100000;
export const HIRE_DEFAULT_TTL_SEC = 3600;
export const HIRE_MIN_TTL_SEC = 60;
export const HIRE_MAX_TTL_SEC = 72 * 3600;
export const RL_HIRE_MAX = 40;
export const RL_HIRE_WINDOW_SEC = 60;
export const EXPIRE_HIRE_BATCH = 40;

/* Standing Orders (agent subscriptions) */
export const SYSTEM_STANDING = "system/standing";
export const STANDING_MIN = 0.000001;
export const STANDING_MAX = 100000;
export const STANDING_MIN_INTERVAL_SEC = 30;
export const STANDING_MAX_INTERVAL_SEC = 30 * 24 * 3600; // 30d
export const STANDING_DEFAULT_INTERVAL_SEC = 3600;
export const STANDING_MIN_TTL_SEC = 60;
export const STANDING_MAX_TTL_SEC = 720 * 3600;
export const STANDING_DEFAULT_TTL_SEC = 72 * 3600;
export const RL_STANDING_MAX = 30;
export const RL_STANDING_WINDOW_SEC = 60;
export const STANDING_RUN_BATCH = 40;


/* Delegation chains (parent authority / child pocket money) */
export const SYSTEM_DELEGATE = "system/delegate";
export const DELEGATE_MIN = 0.000001;
export const DELEGATE_MAX = 100000;
export const DELEGATE_DEFAULT_TTL_SEC = 3600;
export const DELEGATE_MIN_TTL_SEC = 30;
export const DELEGATE_MAX_TTL_SEC = 72 * 3600;
export const RL_DELEGATE_MAX = 40;
export const RL_DELEGATE_WINDOW_SEC = 60;
export const EXPIRE_DELEGATE_BATCH = 50;


/* Dispute / Arbitration (supreme court for work claims) */
export const SYSTEM_DISPUTE = "system/dispute";
export const DISPUTE_MIN = 0.000001;
export const DISPUTE_MAX = 100000;
export const DISPUTE_DEFAULT_TTL_SEC = 72 * 3600; // 72h court window
export const DISPUTE_MIN_TTL_SEC = 300;
export const DISPUTE_MAX_TTL_SEC = 720 * 3600;
export const DISPUTE_DEFAULT_COMPLAINANT_BOND_BPS = 500; // 5% of claim
export const DISPUTE_DEFAULT_ARBITER_BOND_BPS = 200;     // 2% of claim
export const DISPUTE_MIN_ARBITERS = 1;
export const DISPUTE_MAX_ARBITERS = 7;
export const RL_DISPUTE_MAX = 30;
export const RL_DISPUTE_WINDOW_SEC = 60;
export const EXPIRE_DISPUTE_BATCH = 40;

/* ─── Hardening defaults (do not loosen without review) ─── */
export const RL_IP_POST_MAX = 120;             // global per-IP POST budget
export const RL_IP_POST_WINDOW_SEC = 60;
export const INTEGRITY_SAMPLE_LIMIT = 500;     // max accounts scanned per integrity run
