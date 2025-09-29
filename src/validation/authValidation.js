exports.patterns = {
  username: /^[A-Za-z0-9_]{4,30}$/,
  fullName: /^[A-Za-z ,.'-]{2,100}$/,
  idNumber: /^\d{13}$/,
  accountNumber: /^\d{8,12}$/,
  password: /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/
}
