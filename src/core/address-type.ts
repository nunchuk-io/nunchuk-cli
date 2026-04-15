export type AddressType = "NATIVE_SEGWIT" | "NESTED_SEGWIT" | "LEGACY" | "TAPROOT";

export const ADDRESS_TYPES: AddressType[] = ["NATIVE_SEGWIT", "NESTED_SEGWIT", "LEGACY", "TAPROOT"];

export const ADDRESS_TYPE_TO_NUMBER: Record<AddressType, number> = {
  LEGACY: 1,
  NESTED_SEGWIT: 2,
  NATIVE_SEGWIT: 3,
  TAPROOT: 4,
};

export const ADDRESS_TYPE_LABELS: Record<number, AddressType> = {
  1: "LEGACY",
  2: "NESTED_SEGWIT",
  3: "NATIVE_SEGWIT",
  4: "TAPROOT",
};

export function addressTypeToNumber(addressType: AddressType): number {
  return ADDRESS_TYPE_TO_NUMBER[addressType];
}

export function numberToAddressType(addressType: number): AddressType {
  const label = ADDRESS_TYPE_LABELS[addressType];
  if (!label) {
    throw new Error(`Unknown address type: ${addressType}`);
  }
  return label;
}

export function coerceAddressType(addressType: AddressType | number): AddressType {
  if (typeof addressType === "number") {
    return numberToAddressType(addressType);
  }
  if (!ADDRESS_TYPES.includes(addressType)) {
    throw new Error(`Unknown address type: ${addressType}`);
  }
  return addressType;
}

export function formatAddressType(addressType: AddressType | number): AddressType | number {
  return typeof addressType === "number"
    ? (ADDRESS_TYPE_LABELS[addressType] ?? addressType)
    : addressType;
}
