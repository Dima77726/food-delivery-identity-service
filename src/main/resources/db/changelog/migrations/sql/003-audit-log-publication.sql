-- Журнал административных действий сам служит outbox для сводного журнала в insights-service.
-- То же устройство, что у журнала order-service: отметку ставит только публикатор, содержимое
-- записи не меняется, а записи до миграции уезжают первыми — история переносится сама.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ;

COMMENT ON COLUMN audit_log.published_at IS 'Когда запись подтверждена Kafka; NULL — ещё не отправлена в сводный журнал';

CREATE INDEX IF NOT EXISTS idx_audit_log_unpublished
    ON audit_log (id)
    WHERE published_at IS NULL;
