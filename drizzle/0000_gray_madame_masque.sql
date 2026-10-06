CREATE TABLE `vault` (
	`id` integer PRIMARY KEY NOT NULL,
	`envelope` text NOT NULL,
	`write_hash` text NOT NULL,
	`revision` integer DEFAULT 1 NOT NULL
);
