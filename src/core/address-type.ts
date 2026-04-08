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

export function formatAddressType(addressType: number): AddressType | number {
  return ADDRESS_TYPE_LABELS[addressType] ?? addressType;
}
