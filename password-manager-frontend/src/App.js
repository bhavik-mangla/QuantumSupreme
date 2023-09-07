import React from "react";
import RegistrationForm from "./components/RegistrationForm";
import LoginForm from "./components/LoginForm";
import PasswordManager from "./components/PasswordManager";

function App() {
  return (
    <div className="App">
      <h1>Password Manager</h1>
      <RegistrationForm />
      <LoginForm />
      <PasswordManager />
    </div>
  );
}

export default App;
