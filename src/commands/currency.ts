import { Command } from "commander";
import { convertAmount, fetchMarketRates, formatAmount } from "../core/currency.js";
import { print, printError } from "../output.js";

export const currencyCommand = new Command("currency").description("Currency conversion commands");

currencyCommand
  .command("convert")
  .description("Convert between BTC, sat, USD, and fiat currencies")
  .argument("<amount>", "Amount to convert")
  .argument("<from>", "Source currency")
  .argument("<to>", "Target currency")
  .action(async (amountInput, from, to, _options, cmd) => {
    try {
      const amount = Number(amountInput);
      if (!Number.isFinite(amount) || amount < 0) {
        printError(
          {
            error: "INVALID_AMOUNT",
            message: "Amount must be a non-negative number",
          },
          cmd,
        );
        return;
      }

      const rates = await fetchMarketRates();
      const result = convertAmount(amount, from, to, rates);
      const converted = formatAmount(result.converted, result.to);
      print(
        {
          amount,
          from: result.from,
          converted,
          to: result.to,
          display: `${formatAmount(amount, result.from)} ${result.from} = ${converted} ${result.to}`,
        },
        cmd,
      );
    } catch (err) {
      printError(
        {
          error: "CONVERSION_FAILED",
          message: err instanceof Error ? err.message : String(err),
        },
        cmd,
      );
    }
  });
