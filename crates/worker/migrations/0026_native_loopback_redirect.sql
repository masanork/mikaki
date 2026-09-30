-- The registered loopback URI retains port 0 and remains the authorization
-- code's foreign-key target. The actual ephemeral-port URI is separately bound
-- to the code and compared verbatim at exchange. Existing codes have no
-- override and continue to use their registered redirect URI.
ALTER TABLE authorization_code ADD COLUMN redirect_uri_actual TEXT NOT NULL DEFAULT ''
  CHECK(redirect_uri_actual = '' OR length(redirect_uri_actual) BETWEEN 1 AND 2048);
CREATE TRIGGER authorization_code_actual_redirect_immutable
BEFORE UPDATE OF redirect_uri_actual ON authorization_code
WHEN NEW.redirect_uri_actual IS NOT OLD.redirect_uri_actual
BEGIN SELECT RAISE(ABORT, 'authorization-code redirect is immutable'); END;
