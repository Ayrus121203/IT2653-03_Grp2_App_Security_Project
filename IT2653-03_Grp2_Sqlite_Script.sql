--
-- File generated with SQLiteStudio v3.3.3 on Fri Aug 19 00:17:40 2022
--
-- Text encoding used: System
--
PRAGMA foreign_keys = off;
BEGIN TRANSACTION;

-- Table: alembic_version
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO alembic_version (version_num) VALUES ('662d9e12bd05');

-- Table: posts
CREATE TABLE posts (
	id INTEGER NOT NULL, 
	title VARCHAR(255), 
	content TEXT, 
	date_posted DATETIME, 
	slug VARCHAR(255), 
	poster_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(poster_id) REFERENCES users (id)
);

-- Table: used_pass
CREATE TABLE used_pass (
	id INTEGER NOT NULL, 
	password VARCHAR, 
	pass_user_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(pass_user_id) REFERENCES users (id)
);

-- Table: users
CREATE TABLE users (
	id INTEGER NOT NULL, 
	username VARCHAR(20) NOT NULL, 
	name VARCHAR(200), 
	email VARCHAR(120), 
	dob VARCHAR, 
	about_author TEXT(500), 
	profile_pic VARCHAR, 
	date_added DATETIME, 
	address VARCHAR, 
	tel_phone VARCHAR, 
	gender VARCHAR, 
	acc_lockout_counter INTEGER, 
	password_hash VARCHAR, 
	git_id VARCHAR(500), 
	google_id VARCHAR(500), 
	user_secure_question_attempt INTEGER, 
	counter VARCHAR(300), 
	login_count INTEGER, 
	PRIMARY KEY (id), 
	UNIQUE (address), 
	UNIQUE (email), 
	UNIQUE (tel_phone), 
	UNIQUE (username)
);

-- Table: users_log
CREATE TABLE users_log (
	id INTEGER NOT NULL, 
	login_counter VARCHAR(300), 
	userid INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(userid) REFERENCES users (id)
);

-- Table: users_security_question
CREATE TABLE users_security_question (
	id INTEGER NOT NULL, 
	security_question_id VARCHAR, 
	security_answer VARCHAR, 
	user_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id), 
	UNIQUE (security_question_id)
);

COMMIT TRANSACTION;
PRAGMA foreign_keys = on;
