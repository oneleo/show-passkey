export const stringify = (info: any, space?: string | number) =>
  JSON.stringify(
    info,
    (_, value) => {
      return typeof value === "bigint" ? value.toString() : value;
    },
    space
  );
