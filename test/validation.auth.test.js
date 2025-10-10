const { patterns } = require('../src/validation/authValidation');

describe('validation patterns', () => {
  test('username: 4-30 alnum/underscore', () => {
    expect(patterns.username.test('user_1')).toBe(true);
    expect(patterns.username.test('u')).toBe(false);
    expect(patterns.username.test('contains-dash')).toBe(false);
  });

  test('fullName: letters and punctuation 2-100', () => {
    expect(patterns.fullName.test("Tiffany Mather")).toBe(true);
    expect(patterns.fullName.test("O'Neill")).toBe(true);
    expect(patterns.fullName.test('A')).toBe(false);
  });

  test('idNumber: exactly 13 digits', () => {
    expect(patterns.idNumber.test('1234567890123')).toBe(true);
    expect(patterns.idNumber.test('123')).toBe(false);
  });

  test('accountNumber: 8-12 digits', () => {
    expect(patterns.accountNumber.test('12345678')).toBe(true);
    expect(patterns.accountNumber.test('1234567')).toBe(false);
  });

  test('password: strong (letter, number, special, >=8)', () => {
    expect(patterns.password.test('Aa1!aaaa')).toBe(true);
    expect(patterns.password.test('password')).toBe(false);
    expect(patterns.password.test('Aa1aaaaa')).toBe(false); // missing special
  });
});
