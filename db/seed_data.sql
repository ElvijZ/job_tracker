USE jobtracker;

INSERT INTO users (username, email, is_admin, password_hash)
VALUES
  ('admin', 'zepselvijs18@gmail.com', 1, '$2y$10$9BTLr3rdrXxj4A2WJ0Xv2eo0kA0Q8s3AU4m/8lQ2LJvjJ5ndHsm8u')
ON DUPLICATE KEY UPDATE username = VALUES(username), is_admin = VALUES(is_admin);

INSERT INTO users (username, email, password_hash)
VALUES
  ('demo_user', 'demo@example.com', '$2y$10$9BTLr3rdrXxj4A2WJ0Xv2eo0kA0Q8s3AU4m/8lQ2LJvjJ5ndHsm8u')
ON DUPLICATE KEY UPDATE username = VALUES(username);

INSERT INTO jobs (user_id, company, position, status, status_changed_at, last_action, applied_date, notes)
SELECT u.id, 'Acme Corp', 'Backend Developer', 'applied', NOW(), 'seeded', CURDATE(), 'Initial seeded job.'
FROM users u
WHERE u.username = 'demo_user'
AND NOT EXISTS (
  SELECT 1 FROM jobs j WHERE j.user_id = u.id AND j.company = 'Acme Corp' AND j.position = 'Backend Developer'
);

INSERT INTO jobs (user_id, company, position, status, status_changed_at, last_action, applied_date, notes)
SELECT u.id, 'Globex', 'Full Stack Engineer', 'interview', NOW(), 'seeded', CURDATE(), 'Interview round in progress.'
FROM users u
WHERE u.username = 'demo_user'
AND NOT EXISTS (
  SELECT 1 FROM jobs j WHERE j.user_id = u.id AND j.company = 'Globex' AND j.position = 'Full Stack Engineer'
);
