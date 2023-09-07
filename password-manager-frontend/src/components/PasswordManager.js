import React, { useState, useEffect } from "react";
import axios from "axios";

function PasswordManager() {
  const [passwords, setPasswords] = useState([]);
  const [username, setUsername] = useState("");
  const [sitename, setSitename] = useState("");
  const [newPassword, setNewPassword] = useState("");

  const fetchPasswords = async () => {
    try {
      const response = await axios.get("http://127.0.0.1:5000/passwords", {
        params: { username: username }, // Pass the username as a query parameter
      });

      setPasswords(response.data.passwords);
    } catch (error) {
      console.error(error);
    }
  };

  const handleStorePassword = async () => {
    try {
      await axios.post("http://127.0.0.1:5000/store-password", {
        username: username,
        sitename: sitename,
        password: newPassword,
      });
      console.log("Password stored successfully!");
      fetchPasswords(); // Refresh the password list
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    fetchPasswords();
  }, []);
  return (
    <div>
      <h2>Password Manager</h2>
      <div>
        <h3>Stored Passwords:</h3>
        <ul>
          {passwords.map((item, index) => (
            <li key={index}>
              <strong>Site Name: </strong>
              {item.sitename}
              <br />
              <strong>Password: </strong>
              {item.password}
            </li>
          ))}
        </ul>
      </div>
      <div>
        <h3>Store New Password:</h3>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <br />
        <input
          type="text"
          placeholder="Site Name"
          value={sitename}
          onChange={(e) => setSitename(e.target.value)}
        />
        <input
          type="text"
          placeholder="New Password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
        />
        <button onClick={handleStorePassword}>Store Password</button>
      </div>
    </div>
  );
}

export default PasswordManager;
