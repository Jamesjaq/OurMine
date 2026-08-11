import { resolveDryRun } from "./exec_options.ts"
/**
 * @module financial
 * Financial Systems Fraud & Security Controls — ACH Transfer Manipulation Indicators,
 * Wire Fraud Protocol Simulators, SWIFT MT103 Message Format Parser, and Banking API Auditing.
 */

export interface SWIFTMessage {
  senderBIC: string;
  receiverBIC: string;
  amount: number;
  currency: string;
  reference: string;
  valueDate?: string;
  orderingCustomer?: string;
  beneficiary?: string;
  detailsOfCharges?: string;
  senderCorrespondent?: string;
  receiverCorrespondent?: string;
  bankOperationCode?: string;
  transactionType?: string;
  parsingErrors: string[];
}

interface MT103Field {
  tag: string;
  content: string;
}

function parseSWIFTFields(rawMessage: string): MT103Field[] {
  const fields: MT103Field[] = [];
  const lines = rawMessage.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    const tagMatch = trimmed.match(/^(\d{2}[A-Z]?)(:)(.*)/);
    if (tagMatch) {
      fields.push({
        tag: tagMatch[1],
        content: tagMatch[3].trim(),
      });
    }
  }
  return fields;
}

function parseField32A(content: string): { valueDate: string; currency: string; amount: number } | null {
  const match = content.match(/^(\d{6})([A-Z]{3})([\d,]+)$/);
  if (!match) return null;

  const yy = match[1].substring(0, 2);
  const mm = match[1].substring(2, 4);
  const dd = match[1].substring(4, 6);
  const year = parseInt(yy, 10) + 2000;
  const amountStr = match[3].replace(",", ".");
  const amount = parseFloat(amountStr);

  if (isNaN(amount)) return null;

  return {
    valueDate: `${year}-${mm}-${dd}`,
    currency: match[2],
    amount,
  };
}

function parseField50K(content: string): string {
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  return lines.join(", ");
}

function extractNameAccount(lines: string[]): { name: string; account?: string } {
  let name = "";
  let account: string | undefined;

  for (const line of lines) {
    const accountMatch = line.match(/\/(\w[\w-]*)/);
    if (accountMatch) {
      account = accountMatch[1];
    } else if (!name && line.length > 0) {
      name = line;
    }
  }

  return { name, account };
}

export function parseMT103(rawMessage: string, dryRun: boolean = true): SWIFTMessage {
  if (dryRun) {
    return {
      senderBIC: "BOFAUS3NXXX",
      receiverBIC: "DEUTDEFFXXX",
      amount: 24750.00,
      currency: "USD",
      reference: "INV-2024-08812",
      valueDate: "2024-11-15",
      orderingCustomer: "ACME CORP, 123 BROADWAY, NEW YORK, US",
      beneficiary: "GLOBEX INTERNATIONAL, 45 MARKET ST, FRANKFURT, DE",
      detailsOfCharges: "SHA",
      senderCorrespondent: "BOFAUS3N",
      receiverCorrespondent: "DEUTDEFF",
      bankOperationCode: "CRED",
      transactionType: "MT103",
      parsingErrors: [],
    };
  }

  const errors: string[] = [];
  const fields = parseSWIFTFields(rawMessage);

  if (fields.length === 0) {
    errors.push("No valid SWIFT fields parsed from input");
    return {
      senderBIC: "",
      receiverBIC: "",
      amount: 0,
      currency: "",
      reference: "",
      parsingErrors: errors,
    };
  }

  let senderBIC = "";
  let receiverBIC = "";
  let amount = 0;
  let currency = "";
  let reference = "";
  let valueDate = "";
  let orderingCustomer = "";
  let beneficiary = "";
  let detailsOfCharges = "";
  let senderCorrespondent = "";
  let receiverCorrespondent = "";
  let bankOperationCode = "";
  let transactionType = "";

  for (const field of fields) {
    switch (field.tag) {
      case "20":
        reference = field.content;
        break;

      case "23B":
        bankOperationCode = field.content;
        break;

      case "23E":
        transactionType = field.content;
        break;

      case "32A": {
        const parsed = parseField32A(field.content);
        if (parsed) {
          valueDate = parsed.valueDate;
          currency = parsed.currency;
          amount = parsed.amount;
        } else {
          errors.push(`Malformed field 32A: ${field.content}`);
        }
        break;
      }

      case "33B":
        if (!currency) {
          const currMatch = field.content.match(/^([A-Z]{3})([\d,]+)$/);
          if (currMatch) {
            currency = currMatch[1];
            const amt = parseFloat(currMatch[2].replace(",", "."));
            if (!isNaN(amt)) amount = amt;
          }
        }
        break;

      case "50K":
      case "50F": {
        const lines = field.content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        const parsed = extractNameAccount(lines);
        orderingCustomer = parsed.name;
        if (parsed.account) {
          orderingCustomer += ` [Account: ${parsed.account}]`;
        }
        break;
      }

      case "52A":
      case "52D":
        senderCorrespondent = field.content.replace(/\n/g, ", ");
        break;

      case "56A":
      case "56D":
        receiverCorrespondent = field.content.replace(/\n/g, ", ");
        break;

      case "57A":
      case "57D": {
        const bicMatch = field.content.match(/^([A-Z]{6}[A-Z2-9][A-Z0-9]([A-Z0-9]{3})?)/);
        if (bicMatch) {
          receiverBIC = bicMatch[1];
        }
        break;
      }

      case "59":
      case "59A": {
        const lines = field.content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        const parsed = extractNameAccount(lines);
        beneficiary = parsed.name;
        if (parsed.account) {
          beneficiary += ` [Account: ${parsed.account}]`;
        }
        break;
      }

      case "71A":
        detailsOfCharges = field.content;
        break;

      case "71G":
        break;

      default:
        break;
    }
  }

  const bicLine = rawMessage.match(/^{1:(\w{4}\w{2}\w{2}[A-Z0-9]{3}\w*)}/);
  if (bicLine) {
    senderBIC = bicLine[1];
  }

  const finLine = rawMessage.match(/^{2:(\w{4}\w{2}\w{2}[A-Z0-9]{3}\w*)}/);
  if (finLine) {
    receiverBIC = finLine[1];
  }

  if (!reference) errors.push("Missing field 20 (Transaction Reference)");
  if (amount === 0) errors.push("Missing or malformed field 32A (Amount)");
  if (!currency) errors.push("Missing currency code");
  if (!orderingCustomer) errors.push("Missing field 50K (Ordering Customer)");
  if (!beneficiary) errors.push("Missing field 59 (Beneficiary)");
  if (!detailsOfCharges) errors.push("Missing field 71A (Details of Charges)");

  return {
    senderBIC,
    receiverBIC,
    amount,
    currency,
    reference,
    valueDate,
    orderingCustomer,
    beneficiary,
    detailsOfCharges,
    senderCorrespondent,
    receiverCorrespondent,
    bankOperationCode,
    transactionType,
    parsingErrors: errors,
  };
}

export default { parseMT103 };
