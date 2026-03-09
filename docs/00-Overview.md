# Metria Project - Overview

## Purpose

Metria Project is the backend API for the Metria platform. It is responsible for:

- Authentication and token issuance
- Google OAuth callback integration
- User profile and onboarding status
- Assessment persistence
- Goals and sub-goals management
- Billing orchestration with Stripe

## Scope

- Expose HTTP API for `metria-web`
- Persist domain data in PostgreSQL
- Validate and process Stripe webhook events
- Keep subscription state synchronized for paywall checks

## Out of Scope

- Frontend rendering and route orchestration
- Email worker queue processing
- Stripe dashboard configuration lifecycle

## Tech Stack

- ASP.NET Core Minimal APIs (.NET 9)
- Entity Framework Core + Npgsql
- JWT Bearer Authentication
- Stripe.net SDK
- Dockerfile-based deployment on Railway
