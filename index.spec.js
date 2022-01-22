const Vigenere = require("./index.js");

describe("Vigenere class errors", function () {
  it("should throw 'Invalid type'", function () {
    const options = {
      type: "invalid",
    };
    expect(() => new Vigenere(options)).toThrow(
      "Invalid type provided. Available options are: numbers, custom, lowercase, uppercase, symbols, base64, alphanumeric, ascii;"
    );
  });

  it("should throw {character} is required when 'custom' type", function () {
    const options01 = { type: "custom" };
    const options02 = { type: "custom", characters: "" };
    const options03 = { type: "custom", characters: null };
    const options04 = { type: "custom", characters: ["abc"] };
    expect(() => new Vigenere(options01)).toThrow(
      "Characters must be specified when using custom character type."
    );
    expect(() => new Vigenere(options02)).toThrow(
      "Characters must be specified when using custom character type."
    );
    expect(() => new Vigenere(options03)).toThrow(
      "Characters must be specified when using custom character type."
    );
    expect(() => new Vigenere(options04)).toThrow(
      "Custom characters must be a non-empty string."
    );
  });
});
