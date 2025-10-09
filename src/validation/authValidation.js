exports.patterns = {
  //username: 4-30 chars, letters, numbers, or underscore; prevents injection or unsafe characters
  // eslint-disable-next-line no-useless-escape
  username: /^[A-Za-z0-9_]{4,30}$/,

  //full name: 2-100 chars, letters, spaces, and common punctuation; restricts unsafe characters
  // eslint-disable-next-line no-useless-escape
  fullName: /^[A-Za-z ,.'-]{2,100}$/,

  //idNumber: exactly 13 digits (e.g., national ID); ensures correct length and format
  // eslint-disable-next-line no-useless-escape
  idNumber: /^\d{13}$/,

  //accountNumber: 8-12 digits; prevents invalid account numbers
  // eslint-disable-next-line no-useless-escape
  accountNumber: /^\d{8,12}$/,

  //password: at least 8 chars, must include letter, number, and special character; enforces strong password
  // eslint-disable-next-line no-useless-escape
  password: /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/
}
