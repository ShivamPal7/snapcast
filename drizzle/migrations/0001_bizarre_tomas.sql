ALTER TABLE "videos" ADD COLUMN "views" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "videos" ADD COLUMN "duration" integer;--> statement-breakpoint
ALTER TABLE "videos" DROP COLUMN "tags";--> statement-breakpoint
ALTER TABLE "videos" DROP COLUMN "transcription";--> statement-breakpoint
ALTER TABLE "videos" DROP COLUMN "caption";--> statement-breakpoint
ALTER TABLE "videos" DROP COLUMN "metadata";