create table `app_users` (
	`id` varchar(36) PRIMARY KEY NOT NULL,
	`age` integer,
	`created_at` timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`email` varchar(191) NOT NULL UNIQUE,
	`email_verified` boolean NOT NULL DEFAULT false,
	`image` text,
	`name` text NOT NULL,
	`updated_at` timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
);

create table `sessions` (
	`id` varchar(36) PRIMARY KEY NOT NULL,
	`created_at` timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`expires_at` timestamp(3) NOT NULL,
	`ip_address` text,
	`token` varchar(191) NOT NULL UNIQUE,
	`updated_at` timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`user_agent` text,
	`user_id` varchar(36) NOT NULL REFERENCES `app_users` (`id`) ON DELETE CASCADE
);

create table `organizations` (
	`id` varchar(36) PRIMARY KEY NOT NULL,
	`created_at` timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`metadata` json,
	`name` text NOT NULL,
	`seats` integer NOT NULL DEFAULT 5,
	`slug` varchar(191) NOT NULL UNIQUE
);

create table `members` (
	`id` varchar(36) PRIMARY KEY NOT NULL,
	`organization_id` varchar(36) NOT NULL REFERENCES `organizations` (`id`) ON DELETE CASCADE,
	`role` text NOT NULL DEFAULT 'member',
	`user_id` varchar(36) NOT NULL REFERENCES `app_users` (`id`) ON DELETE CASCADE
);

create index `members_organization_id_idx` on `members` (`organization_id`);

create unique index `members_organization_id_user_id_uidx` on `members` (`organization_id`, `user_id`);

create index `members_user_id_idx` on `members` (`user_id`);

create index `sessions_user_id_idx` on `sessions` (`user_id`);
