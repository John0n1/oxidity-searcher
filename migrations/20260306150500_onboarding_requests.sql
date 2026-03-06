CREATE TABLE IF NOT EXISTS onboarding_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    organization TEXT NOT NULL,
    team_type TEXT NOT NULL,
    volume_band TEXT NOT NULL,
    journey_stage TEXT NOT NULL,
    timeline TEXT NOT NULL,
    requested_track TEXT NOT NULL,
    primary_need TEXT NOT NULL,
    recommended_path TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    source_page TEXT,
    intake_packet TEXT NOT NULL,
    remote_addr TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_onboarding_requests_created_at
    ON onboarding_requests(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_onboarding_requests_email
    ON onboarding_requests(email);

CREATE INDEX IF NOT EXISTS idx_onboarding_requests_requested_track
    ON onboarding_requests(requested_track);
