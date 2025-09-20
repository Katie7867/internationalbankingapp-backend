exports.patterns = {
  username: /^[A-Za-z0-9_]{4,30}$/,
  fullName: /^[A-Za-z ,.'-]{2,100}$/,
  idNumber: /^\d{13}$/,
  accountNumber: /^\d{8,20}$/,
  amount: /^\d{1,14}(\.\d{1,2})?$/,
  swift: /^[A-Za-z]{6}[A-Za-z0-9]{2}([A-Za-z0-9]{3})?$/
}
