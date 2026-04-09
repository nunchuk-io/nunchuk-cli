import { describe, expect, it } from "vitest";
import {
  getMiniscriptSpendingPlan,
  getMiniscriptSpendingPlans,
  isMiniscriptPlanSatisfied,
  selectMiniscriptSpendingPlan,
} from "../miniscript-spend.js";

describe("miniscript spending plans", () => {
  it("extracts signing paths, signatures, and timelocks", () => {
    const plans = getMiniscriptSpendingPlans(
      "or_d(pk(key_0),and_v(v:multi(2,key_1,key_2,key_3),older(10)))",
    );

    expect(plans).toEqual([
      expect.objectContaining({
        lockTime: 0,
        preimageRequirements: [],
        requiredSignatures: 1,
        sequence: 0,
        signerNames: ["key_0"],
        supported: true,
      }),
      expect.objectContaining({
        lockTime: 0,
        preimageRequirements: [],
        requiredSignatures: 2,
        sequence: 10,
        signerNames: ["key_1", "key_2", "key_3"],
        supported: true,
      }),
    ]);
  });

  it("selects the first supported plan by default", () => {
    const plan = selectMiniscriptSpendingPlan(
      "or_d(pk(key_0),and_v(v:multi(2,key_1,key_2,key_3),older(10)))",
    );

    expect(plan.index).toBe(0);
    expect(plan.requiredSignatures).toBe(1);
    expect(plan.sequence).toBe(0);
  });

  it("selects an explicit miniscript signing path by index", () => {
    const plan = selectMiniscriptSpendingPlan(
      "or_d(pk(key_0),and_v(v:multi(2,key_1,key_2,key_3),older(10)))",
      undefined,
      1,
    );

    expect(plan.index).toBe(1);
    expect(plan.requiredSignatures).toBe(2);
    expect(plan.sequence).toBe(10);
    expect(
      getMiniscriptSpendingPlan("or_d(pk(key_0),and_v(v:multi(2,key_1,key_2,key_3),older(10)))", 1),
    ).toEqual(plan);
  });

  it("selects a satisfiable plan from locktime and sequence", () => {
    const plan = selectMiniscriptSpendingPlan("or_i(pk(key_0),and_v(v:pk(key_1),older(10)))", {
      inputs: [{ nSequence: 10 }],
      lockTime: 0,
    });

    expect(plan.signerNames).toEqual(["key_0"]);
    expect(
      isMiniscriptPlanSatisfied(getMiniscriptSpendingPlans("and_v(v:pk(key_1),older(10))")[0], {
        inputs: [{ nSequence: 10 }],
        lockTime: 0,
      }),
    ).toBe(true);
  });

  it("supports hash-preimage-only paths", () => {
    const plan = selectMiniscriptSpendingPlan(
      "sha256(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
    );

    expect(plan.supported).toBe(true);
    expect(plan.requiredSignatures).toBe(0);
    expect(plan.preimageRequirements).toEqual([
      {
        hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        type: "SHA256",
      },
    ]);
  });

  it("rejects unknown or unsatisfied explicit path selections", () => {
    expect(() =>
      selectMiniscriptSpendingPlan("or_d(pk(key_0),and_v(v:pk(key_1),older(10)))", undefined, 9),
    ).toThrow("Unknown miniscript signing path: 9");

    expect(() =>
      selectMiniscriptSpendingPlan(
        "or_d(pk(key_0),and_v(v:pk(key_1),older(10)))",
        { inputs: [{ nSequence: 0 }], lockTime: 0 },
        1,
      ),
    ).toThrow("Selected miniscript signing path is not satisfiable: 1");
  });
});
