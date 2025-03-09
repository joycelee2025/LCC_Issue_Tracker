CREATE TABLE `users` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(20) NOT NULL,
  `password_hash` char(60) BINARY NOT NULL COMMENT 'Bcrypt Password Hash and Salt (60 bytes)',
  `email` varchar(320) NOT NULL COMMENT 'Maximum email address length according to RFC5321 section 4.5.3.1 is 320 characters (64 for local-part, 1 for at sign, 255 for domain)',
  `first_name` varchar(50) NOT NULL,
  `last_name` varchar(50) NOT NULL,
  `location` varchar(50) NOT NULL,
  `profile_image' varchar(255),
  `role` enum('visitor','helper','admin') NOT NULL,
  `status` enum('active','inactive') NOT NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `username` (`username`)
)

CREATE TABLE `issues` (
  `issue_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `summary` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `created_at` timestamp NOT NULL,
  `status` enum('new', 'open', 'stalled', 'resolved') NOT NULL,
  PRIMARY KEY (`issue_id`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
)

CREATE TABLE `comments` (
  `comment_id` int NOT NULL AUTO_INCREMENT,
  `issue_id` int NOT NULL,
  `user_id` int NOT NULL,
  `content` text NOT NULL,
  `created_at` timestamp NOT NULL,
  PRIMARY KEY (`comment_id`),
  FOREIGN KEY (`issue_id`) REFERENCES `issues` (`issue_id`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
)