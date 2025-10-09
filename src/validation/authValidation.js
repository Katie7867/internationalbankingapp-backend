exports.patterns = {
  // eslint-disable-next-line no-useless-escape
  username: /^[A-Za-z0-9_]{4,30}$/,
  // eslint-disable-next-line no-useless-escape
  fullName: /^[A-Za-z ,.'-]{2,100}$/,
  // eslint-disable-next-line no-useless-escape
  idNumber: /^\d{13}$/,
  // eslint-disable-next-line no-useless-escape
  accountNumber: /^\d{8,12}$/,
  // eslint-disable-next-line no-useless-escape
  password: /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/
}
