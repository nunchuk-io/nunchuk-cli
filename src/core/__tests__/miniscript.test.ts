import { describe, expect, it } from "vitest";
import {
  UNDETERMINED_TIMELOCK_VALUE,
  buildMiniscriptDescriptor,
  createTimelock,
  decayingMultisigMiniscriptTemplate,
  expandingMultisigMiniscriptTemplate,
  flexibleMultisigMiniscriptTemplate,
  getAllSigningPaths,
  getCoinsGroupedBySubPolicies,
  getScriptNode,
  getTimelockedCoins,
  isNodeSatisfiable,
  isValidMiniscriptTemplate,
  isValidPolicy,
  isValidTapscriptTemplate,
  miniscriptTemplateToMiniscript,
  MiniscriptTimeline,
  parseSignerNames,
  parseTapscriptTemplate,
  policyToMiniscript,
  scriptNodeToString,
  tapscriptTemplateToTapscript,
  validateTapscriptTemplate,
} from "../miniscript.js";

const HEIGHT_RELATIVE_LOCK = createTimelock("HEIGHT_LOCK", "LOCKTYPE_RELATIVE", 1);
const TEST_SIGNERS: Record<string, string> = {
  key_0_0:
    "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  key_0_1:
    "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  key_1_0:
    "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
  key_1_1:
    "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
  key_2_1:
    "[87e4f1b3/48'/1'/0'/2']tpubDEQh9EEu9xKQzM5jNa11p7Y7e8dQ2V3v8A7RVxJxQv7iH6e9aX9kQpQy9uZL5nP6h4g1c3e2v7m8r9s0t1u2w3x4y5z6",
  key_3:
    "[11111111/48'/1'/0'/2']tpubD6NzVbkrYhZ4X1example11111111111111111111111111111111111111111",
  key_4:
    "[22222222/48'/1'/0'/2']tpubD6NzVbkrYhZ4X1example22222222222222222222222222222222222222222",
};

describe("miniscript templates", () => {
  it("builds expanding multisig for native segwit", () => {
    expect(
      expandingMultisigMiniscriptTemplate(2, 2, 3, true, HEIGHT_RELATIVE_LOCK, "NATIVE_SEGWIT"),
    ).toBe("or_d(multi(2,key_0_0,key_1_0),and_v(v:multi(2,key_0_1,key_1_1,key_2_0),older(1)))");
  });

  it("builds decaying multisig for native segwit", () => {
    expect(
      decayingMultisigMiniscriptTemplate(2, 2, 1, true, HEIGHT_RELATIVE_LOCK, "NATIVE_SEGWIT"),
    ).toBe("or_d(multi(2,key_0_0,key_1_0),and_v(v:multi(1,key_0_1,key_1_1),older(1)))");
  });

  it("builds flexible multisig for taproot", () => {
    expect(
      flexibleMultisigMiniscriptTemplate(2, 2, 1, 3, false, HEIGHT_RELATIVE_LOCK, "TAPROOT"),
    ).toBe("{multi_a(2,key_0_0,key_1_0),and_v(v:multi_a(1,key_2_0,key_3_0,key_4_0),older(1))}");
  });
});

describe("policy conversion", () => {
  it("validates policy syntax", () => {
    expect(isValidPolicy("and(pk(alice),after(144))")).toBe(true);
    expect(isValidPolicy("and(pk(alice),)")).toBe(false);
    expect(isValidPolicy("and(pk(alice),pk(bob),pk(carol))")).toBe(false);
    expect(isValidPolicy("or(0@pk(alice),pk(bob))")).toBe(false);
  });

  it("converts simple policies to miniscript", () => {
    expect(policyToMiniscript("and(pk(alice),after(144))")).toBe("and_v(v:pk(alice),after(144))");
    expect(policyToMiniscript("or(pk(alice),pk(bob))")).toBe("or_b(pk(alice),s:pk(bob))");
  });

  it("converts threshold key policies to multi/multi_a", () => {
    expect(policyToMiniscript("thresh(2,pk(a),pk(b),pk(c))")).toBe("multi(2,a,b,c)");
    expect(policyToMiniscript("thresh(2,pk(a),pk(b),pk(c))", {}, "TAPROOT")).toBe(
      "multi_a(2,a,b,c)",
    );
  });
});

describe("miniscript validation and substitution", () => {
  it("rejects taproot-only fragments in native segwit", () => {
    expect(isValidMiniscriptTemplate("multi_a(2,a,b)", "NATIVE_SEGWIT")).toBe(false);
  });

  it("rejects mixed time- and height-locks", () => {
    expect(isValidMiniscriptTemplate("and_v(v:after(1),after(500000000))", "NATIVE_SEGWIT")).toBe(
      false,
    );
  });

  it("substitutes signer descriptors into miniscript templates", () => {
    expect(miniscriptTemplateToMiniscript("multi(2,key_0_0,key_1_0)", TEST_SIGNERS, "/*")).toBe(
      "multi(2,[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ/*,[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s/*)",
    );
  });

  it("accepts compact wrapper chains in miniscript templates", () => {
    const template = "thresh(3,pk(key_1),s:pk(key_2),s:pk(key_3),sln:older(12960))";

    expect(isValidMiniscriptTemplate(template, "NATIVE_SEGWIT")).toBe(true);
    expect(parseSignerNames(template)).toEqual({
      keypathM: 0,
      names: ["key_1", "key_2", "key_3"],
    });
  });

  it("applies wrappers to constants like libnunchuk", () => {
    expect(miniscriptTemplateToMiniscript("n:0", {}, "")).toBe("n:0");
    expect(miniscriptTemplateToMiniscript("l:1", {}, "")).toBe("l:1");
    expect(miniscriptTemplateToMiniscript("u:1", {}, "")).toBe("u:1");
  });

  it("rejects consecutive verify wrappers like libnunchuk", () => {
    expect(isValidMiniscriptTemplate("vv:pk(key_1)", "NATIVE_SEGWIT")).toBe(false);
  });

  it("rejects separated wrapper groups like libnunchuk", () => {
    expect(isValidMiniscriptTemplate("s:l:n:older(12960)", "NATIVE_SEGWIT")).toBe(false);
  });

  it("rejects empty and separated miniscript arguments like libnunchuk", () => {
    for (const template of [
      "multi(1,key_1,)",
      "multi(1,,key_1)",
      "thresh(1,pk(key_1),)",
      "and_v(v:pk(key_1), pk(key_2))",
    ]) {
      expect(isValidMiniscriptTemplate(template, "NATIVE_SEGWIT")).toBe(false);
    }
  });
});

describe("script tree helpers", () => {
  const template =
    "or_d(multi(2,key_0_0,key_1_0),and_v(v:multi(2,key_0_1,key_1_1,key_2_1),older(1)))";

  it("builds script nodes that match the simplified libnunchuk tree", () => {
    const { keypath, node } = getScriptNode(template);
    expect(keypath).toEqual([]);
    expect(node.type).toBe("OR");
    expect(node.id).toEqual([1]);
    expect(node.subs[0].type).toBe("MULTI");
    expect(node.subs[1].type).toBe("AND");
    expect(scriptNodeToString(node)).toBe(
      "or(multi(2,key_0_0,key_1_0),and(multi(2,key_0_1,key_1_1,key_2_1),older(1)))",
    );
  });

  it("enumerates signing paths", () => {
    const paths = getAllSigningPaths(template);
    expect(paths).toEqual([
      [[1, 1]],
      [
        [1, 2, 1],
        [1, 2, 2],
      ],
    ]);
  });

  it("enumerates threshold signing paths", () => {
    const paths = getAllSigningPaths("thresh(2,pk(a),s:pk(b),s:pk(c))");
    expect(paths).toEqual([
      [
        [1, 1],
        [1, 2],
      ],
      [
        [1, 1],
        [1, 3],
      ],
      [
        [1, 2],
        [1, 3],
      ],
    ]);
  });
});

describe("tapscript helpers", () => {
  const template = "tr(key_0_0,{pk(key_1_0),{pk(key_2_1),pk(musig(key_3,key_4))}})";

  it("parses tapscript templates into leaves and depths", () => {
    expect(parseTapscriptTemplate(template)).toEqual({
      keypath: ["key_0_0"],
      subscripts: ["pk(key_1_0)", "pk(key_2_1)", "pk(musig(key_3,key_4))"],
      depths: [1, 2, 2],
    });
  });

  it("validates tapscript templates and duplicate keys", () => {
    expect(isValidTapscriptTemplate(template)).toBe(true);
    expect(validateTapscriptTemplate("tr(key_0_0,{pk(key_1_0),pk(key_1_0)})")).toEqual({
      error: "duplicate key: 'key_1_0'",
      ok: false,
    });
  });

  it("converts tapscript templates into tapscript strings", () => {
    expect(tapscriptTemplateToTapscript(template, TEST_SIGNERS, "/*")).toEqual({
      keypath: ["key_0_0"],
      tapscript:
        "{pk([4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s/*),{pk([87e4f1b3/48'/1'/0'/2']tpubDEQh9EEu9xKQzM5jNa11p7Y7e8dQ2V3v8A7RVxJxQv7iH6e9aX9kQpQy9uZL5nP6h4g1c3e2v7m8r9s0t1u2w3x4y5z6/*),pk(musig([11111111/48'/1'/0'/2']tpubD6NzVbkrYhZ4X1example11111111111111111111111111111111111111111,[22222222/48'/1'/0'/2']tpubD6NzVbkrYhZ4X1example22222222222222222222222222222222222222222)/*)}}",
    });
  });

  it("builds OR_TAPROOT script trees", () => {
    const { keypath, node } = getScriptNode(template);
    expect(keypath).toEqual(["key_0_0"]);
    expect(node.type).toBe("OR_TAPROOT");
    expect(scriptNodeToString(node.subs[1].subs[1])).toBe("pk(musig(key_3,key_4))");
  });
});

describe("timeline and timelock helpers", () => {
  const relativeScript = "and_v(v:pk(alice),older(10))";

  it("derives lock timelines", () => {
    const timeline = new MiniscriptTimeline(relativeScript);
    expect(timeline.getLockType()).toBe("HEIGHT_LOCK");
    expect(timeline.getRelativeLocks()).toEqual([10]);
    expect(timeline.getLocks({ blocktime: 1_700_000_000, height: 100 })).toEqual([110]);
  });

  it("identifies timelocked coins", () => {
    const result = getTimelockedCoins(
      relativeScript,
      [
        { blocktime: 1_700_000_000, height: 105 },
        { blocktime: 1_700_000_000, height: 50 },
      ],
      100,
      1_700_000_500,
    );
    expect(result.lockedCoins).toEqual([{ blocktime: 1_700_000_000, height: 105 }]);
    expect(result.lockBased).toBe("HEIGHT_LOCK");
    expect(result.maxLockValue).toBe(115);
  });

  it("treats unconfirmed relative-lock coins as undetermined", () => {
    const result = getTimelockedCoins(
      relativeScript,
      [{ blocktime: 0, height: 0 }],
      100,
      1_700_000_500,
    );
    expect(result.maxLockValue).toBe(UNDETERMINED_TIMELOCK_VALUE);
  });

  it("groups coins by unlocked subpolicy", () => {
    const groups = getCoinsGroupedBySubPolicies(
      "or_i(after(120),after(240))",
      [{ blocktime: 0, height: 1 }],
      200,
      1_700_000_500,
    );
    expect(groups).toEqual([
      { coins: [{ blocktime: 0, height: 1 }], maxLockValue: 0 },
      { coins: [], maxLockValue: 240 },
    ]);
  });
});

describe("descriptor and satisfiability helpers", () => {
  it("builds miniscript descriptors", () => {
    expect(buildMiniscriptDescriptor("pk(alice)", "NATIVE_SEGWIT")).toMatch(
      /^wsh\(pk\(alice\)\)#.{8}$/,
    );
  });

  it("checks node satisfiability against tx lock state", () => {
    expect(
      isNodeSatisfiable("and_v(v:pk(alice),older(10))", {
        inputs: [{ nSequence: 10 }],
        lockTime: 0,
      }),
    ).toBe(true);
    expect(
      isNodeSatisfiable("after(200)", {
        inputs: [{ nSequence: 0 }],
        lockTime: 100,
      }),
    ).toBe(false);
  });

  it("extracts signer names with keypath ordering preserved", () => {
    expect(parseSignerNames("tr(key_0_0,{pk(key_1_0),pk(key_2_1)})")).toEqual({
      keypathM: 1,
      names: ["key_0_0", "key_1_0", "key_2_1"],
    });
  });
});
