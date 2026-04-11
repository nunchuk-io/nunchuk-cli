# Webhook Guide

Webhooks allow you to receive real-time HTTP notifications when events happen on your Nunchuk account (e.g., transaction updates, group invitation acceptance, sandbox group state changes). Instead of polling the API, Nunchuk will POST event data to your endpoint automatically.

Webhooks are configured per network. Mainnet and testnet have separate configurations.

## Adding a Webhook Endpoint

1. Log in to the [Nunchuk Developer Portal](https://developer.nunchuk.io).
2. Navigate to **Webhooks** in the sidebar.
3. Click **Add Endpoint**.

### Endpoint URL

Enter the HTTPS URL where you want to receive webhook events. The URL must use `https://`.

Example: `https://yourserver.com/webhooks/nunchuk`

### Description (optional)

A short label to help you identify this endpoint (e.g., "Production server", "Staging alerts").

### Destination Type

Choose the destination type that matches where you want events delivered:

| Type | When to use | Additional settings |
|------|-------------|---------------------|
| **Generic** | Your own server or any custom HTTPS endpoint | None |
| **Slack** | Post events to a Slack channel via incoming webhook | None (use the Slack webhook URL as the endpoint URL) |
| **Telegram** | Send events to a Telegram chat | **Chat ID** — the Telegram chat/group ID to send messages to |
| **WhatsApp** | Send events via WhatsApp Cloud API | **Recipient phone number** — use the WhatsApp Cloud API messages URL as the endpoint URL, and pass the bearer token via custom headers |

Use **Generic** for standard server-to-server integrations. Only select Slack, Telegram, or WhatsApp if you want events delivered directly to those apps.

### Events

By default, **All events** is selected. Your endpoint will receive every event type.

To receive only specific events, uncheck "All events" and select the individual event types you need. Events are grouped by category for easier browsing.

### Custom Headers (optional)

Add custom HTTP headers that will be included in every webhook request. This is useful for:

- Authentication tokens (e.g., `Authorization: Bearer <token>`)
- Custom identifiers to route requests on your server

You can add up to 20 custom headers.

### Save

Click **Add** to create the endpoint. It will immediately start receiving events.

## Managing Endpoints

### Edit

Click the edit icon on any endpoint in the table to update its URL, description, destination type, events, or custom headers.

### Disable

Click the disable icon to stop receiving events at that endpoint. Disabled endpoints are removed from the active list.

## Viewing Events

Switch to the **Events** tab to see delivery logs for all your webhook endpoints.

### Filters

Use the filter bar to narrow down events:

- **Search** — filter by a specific Event ID
- **Endpoint** — show events for a specific endpoint
- **Status** — filter by delivery status (Pending, Running, Succeeded, Failed, Cancelled)
- **Event type** — filter by event type

Click **Reset filters** to clear all filters.

### Event Detail

Click any event in the list to view its details:

- **Event ID** — unique identifier for the event
- **Created** — when the event was generated
- **API version** — the API version used
- **Attempts** — delivery attempts made vs. maximum allowed
- **Status** — HTTP status code and delivery status
- **Send to** — the endpoint URL that received this event
- **Event data** — the full JSON payload

## Destination Type Examples

### Generic (server-to-server)

```
Endpoint URL: https://yourserver.com/webhooks/nunchuk
Destination type: Generic
```

Your server receives a POST request with the event JSON payload in the body.

### Slack

```
Endpoint URL: https://hooks.slack.com/services/TXXXXX/BXXXXX/XXXXXXXXXX
Destination type: Slack
```

Use a Slack incoming webhook URL. Events are formatted and posted to the configured channel.

### Telegram

```
Endpoint URL: https://api.telegram.org/bot<BOT_TOKEN>/sendMessage
Destination type: Telegram
Chat ID: -1001234567890
```

Provide your Telegram bot's API URL and the target chat ID.

### WhatsApp

```
Endpoint URL: https://graph.facebook.com/v21.0/<PHONE_NUMBER_ID>/messages
Destination type: WhatsApp
Recipient phone: 15551234567
Custom headers:
  Authorization: Bearer <WHATSAPP_ACCESS_TOKEN>
```

Use the WhatsApp Cloud API messages URL. Pass the bearer token via custom headers.

## Outbound Webhook Request

When an event is delivered, the backend sends a `POST` request to the endpoint URL with JSON body and these base headers:

```text
Content-Type: application/json
User-Agent: Nunchuk-Webhooks/1.0
Nunchuk-Event-Id: evt_...
Nunchuk-Event-Type: wallet.transaction.updated
Nunchuk-Delivery-Id: wdl_...
Nunchuk-Attempt: 1
```

The user-configured custom headers are appended to the request.

Request body depends on `destination_type`:

- `GENERIC` receives the full Nunchuk webhook JSON envelope.
- `SLACK` receives a Slack incoming-webhook compatible JSON body with a `text` field.
- `TELEGRAM` receives a Telegram `sendMessage` compatible JSON body with `chat_id`, `text`, and `disable_web_page_preview`.
- `WHATSAPP` receives a WhatsApp Cloud API compatible JSON body with `messaging_product`, `to`, `type`, and `text`.

The endpoint should return any 2xx status code for success. Non-2xx responses and network failures are retried. Current max attempts is 8.

Retry delay sequence after failures:

```json
[60, 300, 900, 3600, 10800, 21600, 43200]
```

Values are in seconds.

## Outbound Payload

`SLACK` webhook recipients receive this shape:

```json
{
  "text": "Nunchuk webhook event: wallet.transaction.updated\nEvent ID: evt_...\nCreated time: 1770000000000\nData: {\"wallet_id\":\"wallet_id\",\"wallet_display_id\":\"wallet_display_id\",\"transaction_id\":\"transaction_id\",\"bitcoin_transaction_id\":\"bitcoin_transaction_id\"}"
}
```

`TELEGRAM` webhook recipients receive this shape:

```json
{
  "chat_id": "123456789",
  "text": "Nunchuk webhook event: wallet.transaction.updated\nEvent ID: evt_...\nCreated time: 1770000000000\nData: {\"wallet_id\":\"wallet_id\",\"wallet_display_id\":\"wallet_display_id\",\"transaction_id\":\"transaction_id\",\"bitcoin_transaction_id\":\"bitcoin_transaction_id\"}",
  "disable_web_page_preview": true
}
```

`WHATSAPP` webhook recipients receive this shape:

```json
{
  "messaging_product": "whatsapp",
  "to": "15551234567",
  "type": "text",
  "text": {
    "preview_url": false,
    "body": "Nunchuk webhook event: wallet.transaction.updated\nEvent ID: evt_...\nCreated time: 1770000000000\nData: {\"wallet_id\":\"wallet_id\",\"wallet_display_id\":\"wallet_display_id\",\"transaction_id\":\"transaction_id\",\"bitcoin_transaction_id\":\"bitcoin_transaction_id\"}"
  }
}
```

## Event Payloads

### `group.sandbox.updated`

Triggered when sandbox group state changes.

```json
{
  "id": "evt_...",
  "type": "group.sandbox.updated",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "group_id": "group_id",
    "state_id": 3
  }
}
```

`state_id` is included when available.

### `group.sandbox.finalized`

Triggered when a sandbox group is finalized into a wallet.

```json
{
  "id": "evt_...",
  "type": "group.sandbox.finalized",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "group_id": "group_id",
    "wallet_id": "wallet_id",
    "wallet_display_id": "wallet_display_id"
  }
}
```

`wallet_id` is the shared-wallet API identifier and is included when available. `wallet_display_id` is included when the wallet has a display identifier, for example a platform-key BSMS id.

### `group.deleted`

Triggered when a group is deleted.

```json
{
  "id": "evt_...",
  "type": "group.deleted",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "group_id": "group_id"
  }
}
```

### `wallet.downgraded`

Triggered when a wallet is downgraded.

```json
{
  "id": "evt_...",
  "type": "wallet.downgraded",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "wallet_id": "wallet_id",
    "wallet_display_id": "wallet_display_id"
  }
}
```

`wallet_display_id` is included when available.

### `wallet.replacement_created`

Triggered when a wallet replacement group is created.

```json
{
  "id": "evt_...",
  "type": "wallet.replacement_created",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "wallet_id": "wallet_id",
    "wallet_display_id": "wallet_display_id",
    "replacement_group_id": "group_id"
  }
}
```

`wallet_display_id` and `replacement_group_id` are included when available.

### `wallet.transaction.updated`

Triggered when a wallet transaction is created or updated.

```json
{
  "id": "evt_...",
  "type": "wallet.transaction.updated",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "wallet_id": "wallet_id",
    "wallet_display_id": "wallet_display_id",
    "transaction_id": "transaction_id",
    "bitcoin_transaction_id": "bitcoin_transaction_id"
  }
}
```

`wallet_display_id` and `bitcoin_transaction_id` are included when available.

### `wallet.transaction.deleted`

Triggered when a wallet transaction is deleted.

```json
{
  "id": "evt_...",
  "type": "wallet.transaction.deleted",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "wallet_id": "wallet_id",
    "wallet_display_id": "wallet_display_id",
    "transaction_id": "transaction_id",
    "bitcoin_transaction_id": "bitcoin_transaction_id"
  }
}
```

`wallet_display_id` and `bitcoin_transaction_id` are included when available.

### `wallet.dummy_transaction.updated`

Triggered when a wallet dummy transaction changes.

```json
{
  "id": "evt_...",
  "type": "wallet.dummy_transaction.updated",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "wallet_id": "wallet_id",
    "wallet_display_id": "wallet_display_id",
    "dummy_transaction_id": "dummy_transaction_id"
  }
}
```

`wallet_display_id` is included when available.

### `wallet.platform_key.policy_changed`

Triggered when the completed platform key policy update becomes effective.

```json
{
  "id": "evt_...",
  "type": "wallet.platform_key.policy_changed",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "wallet_id": "wallet_id",
    "wallet_display_id": "wallet_display_id",
    "dummy_transaction_id": "dummy_transaction_id"
  }
}
```

`wallet_display_id` and `dummy_transaction_id` are included when available.

### `group.invitation.created`

Triggered when one or more group invitations are created.

```json
{
  "id": "evt_...",
  "type": "group.invitation.created",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "group_id": "group_id",
    "invitations": [
      {
        "invitation_id": "invitation_id",
        "group_id": "group_id",
        "inviter_user_id": "inviter_user_id",
        "recipient_email": "recipient@example.com",
        "status": "PENDING",
        "created_time_ms": 1770000000000
      }
    ]
  }
}
```

`recipient_user_id` is intentionally not included for this event.

### `group.invitation.accepted`

Triggered when an invited user accepts a group invitation.

```json
{
  "id": "evt_...",
  "type": "group.invitation.accepted",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "group_id": "group_id",
    "recipient_user_id": "recipient_user_id"
  }
}
```

### `group.invitation.removed`

Triggered when a group invitation is removed.

```json
{
  "id": "evt_...",
  "type": "group.invitation.removed",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "invitation_id": "invitation_id",
    "group_id": "group_id",
    "inviter_user_id": "inviter_user_id",
    "recipient_email": "recipient@example.com",
    "status": "REMOVED",
    "created_time_ms": 1770000000000
  }
}
```

`recipient_user_id` is intentionally not included for this event.

### `group.invitation.denied`

Triggered when a group invitation is denied.

```json
{
  "id": "evt_...",
  "type": "group.invitation.denied",
  "api_version": "v1.1",
  "created_time_ms": 1770000000000,
  "data": {
    "invitation_id": "invitation_id",
    "group_id": "group_id",
    "inviter_user_id": "inviter_user_id",
    "recipient_user_id": "recipient_user_id",
    "recipient_email": "recipient@example.com",
    "status": "DENIED",
    "created_time_ms": 1770000000000
  }
}
```
