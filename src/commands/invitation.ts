import { Command } from "commander";
import {
  requireApiKey,
  requireEmail,
  getNetwork,
  loadConfig,
  getEphemeralKeypair,
} from "../core/config.js";
import { ApiClient } from "../core/api-client.js";
import { buildJoinGroupEvent } from "../core/sandbox.js";
import { addSandboxId } from "../core/storage.js";
import { print, printError, printTable, printSandboxResult } from "../output.js";

function requireEphemeralKeys(flagNetwork?: string): { pub: string; priv: string } {
  const config = loadConfig();
  const network = getNetwork(flagNetwork);
  const keys = getEphemeralKeypair(config, network);
  if (!keys?.pub || !keys?.priv) {
    console.error('Error: No ephemeral keys. Run "nunchuk auth login" first.');
    process.exit(1);
  }
  return { pub: keys.pub, priv: keys.priv };
}

function createClient(cmd: Command): ApiClient {
  const globals = cmd.optsWithGlobals();
  return new ApiClient(requireApiKey(globals.apiKey, globals.network), getNetwork(globals.network));
}

type InvitationRecord = {
  id: string;
  inviter_email: string;
  inviter_name: string;
  group_id: string;
};

type InviteResponse = {
  invitations: InvitationRecord[];
};

type GroupInvitationRecord = {
  id: string;
  group_id: string;
  recipient_email: string;
  recipient_user_id: string | null;
  status: string;
  created_time: number | null;
};

type GroupInvitationListResponse = {
  invitations: GroupInvitationRecord[];
};

function isInvitationRecord(
  invitation: InvitationRecord | GroupInvitationRecord,
): invitation is InvitationRecord {
  return "inviter_email" in invitation;
}

function normalizeInviteEmails(inputs: string[]): string[] {
  const seen = new Set<string>();
  const emails: string[] = [];

  for (const input of inputs) {
    for (const part of input.split(",")) {
      const email = part.trim();
      if (!email || seen.has(email)) {
        continue;
      }
      seen.add(email);
      emails.push(email);
    }
  }

  return emails;
}

function printInviteResult(result: InviteResponse, cmd: Command): void {
  print({ status: "success", invited: result.invitations.length }, cmd);
}

function printInvitationListResult(
  result: InviteResponse | GroupInvitationListResponse,
  cmd: Command,
): void {
  const globals = cmd.optsWithGlobals();
  if (globals.json) {
    print(result, cmd);
    return;
  }

  if (result.invitations.length === 0) {
    print({ invitations: [] }, cmd);
    return;
  }

  const first = result.invitations[0];
  if (isInvitationRecord(first)) {
    printTable(
      result.invitations.filter(isInvitationRecord).map((invitation) => ({
        id: invitation.id,
        groupId: invitation.group_id,
        inviterName: invitation.inviter_name,
        inviterEmail: invitation.inviter_email,
      })),
    );
    return;
  }

  printTable(
    result.invitations
      .filter((invitation): invitation is GroupInvitationRecord => !isInvitationRecord(invitation))
      .map((invitation) => ({
        id: invitation.id,
        groupId: invitation.group_id,
        recipientEmail: invitation.recipient_email,
        recipientUserId: invitation.recipient_user_id ?? "",
        status: invitation.status,
        createdTime:
          invitation.created_time == null ? "" : new Date(invitation.created_time).toISOString(),
      })),
  );
}

export const invitationCommand = new Command("invitation").description("Manage wallet invitations");

invitationCommand
  .command("send")
  .description("Invite people to a sandbox by email")
  .argument("<sandbox-id>", "Sandbox ID")
  .argument("<emails...>", "Recipient email addresses")
  .action(async (sandboxId, emails, _options, cmd) => {
    try {
      const client = createClient(cmd);
      const normalizedEmails = normalizeInviteEmails(emails as string[]);

      if (normalizedEmails.length === 0) {
        printError(
          {
            error: "MISSING_PARAM",
            message: "Provide at least one recipient email",
          },
          cmd,
        );
        return;
      }

      const result = await client.post<InviteResponse>(
        "/v1.1/shared-wallets/invitations",
        JSON.stringify({
          group_id: sandboxId,
          emails: normalizedEmails,
        }),
      );
      printInviteResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

invitationCommand
  .command("list")
  .description("List invitations for the current user, or for a sandbox")
  .argument("[sandbox-id]", "Optional sandbox ID")
  .action(async (sandboxId, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const client = createClient(cmd);

      if (sandboxId) {
        const result = await client.get<GroupInvitationListResponse>(
          `/v1.1/shared-wallets/invitations/groups/${sandboxId}`,
        );
        const email = requireEmail(globals.network).toLowerCase();
        printInvitationListResult(
          {
            invitations: result.invitations.filter(
              (invitation) => invitation.recipient_email.toLowerCase() !== email,
            ),
          },
          cmd,
        );
        return;
      }

      const result = await client.get<InviteResponse>("/v1.1/shared-wallets/invitations");
      printInvitationListResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

invitationCommand
  .command("accept")
  .description("Accept an invitation and join its sandbox")
  .argument("<invitation-id>", "Invitation ID")
  .action(async (invitationId, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const client = createClient(cmd);

      const invitations = await client.get<InviteResponse>("/v1.1/shared-wallets/invitations");
      const invitation = invitations.invitations.find((item) => item.id === invitationId);
      if (!invitation) {
        printError(
          {
            error: "NOT_FOUND",
            message: `Invitation ${invitationId} not found`,
          },
          cmd,
        );
        return;
      }

      const groupData = await client.get<{ group: Record<string, unknown> }>(
        `/v1.1/shared-wallets/groups/${invitation.group_id}`,
      );
      const { pub } = requireEphemeralKeys(globals.network);
      const body = buildJoinGroupEvent(invitation.group_id, groupData.group, pub);
      await client.post("/v1.1/shared-wallets/groups/join", body);

      addSandboxId(email, network, invitation.group_id);
      const result = await client.get(`/v1.1/shared-wallets/groups/${invitation.group_id}`);
      printSandboxResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

invitationCommand
  .command("deny")
  .description("Deny an invitation")
  .argument("<invitation-id>", "Invitation ID")
  .action(async (invitationId, _options, cmd) => {
    try {
      const client = createClient(cmd);
      await client.post(`/v1.1/shared-wallets/invitations/${invitationId}/deny`);
      print({ status: "denied", invitationId }, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
