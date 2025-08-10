import React, { useEffect, useState } from "react";
import styled from "styled-components";
import { useAtom } from "jotai";
import { Input } from "antd";
import { useGlobalContext } from "@/context/globalContext";
import authScreenAtom from "@/atoms/authAtom";
import Button from "@/components/Button";

function LoginCard() {
  const { handleLogin } = useGlobalContext();
  const [inputs, setInputs] = useState({
    emailOrUsername: "",
    password: "",
  });

  const [allFieldsFilled, setAllFieldsFilled] = useState(false);
  const [, setAuthScreen] = useAtom(authScreenAtom);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setInputs((prevInputs) => ({
      ...prevInputs,
      [name]: value,
    }));
  };

  useEffect(() => {
    const allFields = Object.keys(inputs).every(
      (key) => inputs[key] !== null && inputs[key] !== ""
    );
    setAllFieldsFilled(allFields);
  }, [inputs]);

  const handlePasswordKeyPress = (event) => {
    if (event.key === "Enter") {
      handleSubmit();
    }
  };

  const handleSubmit = async () => {
    const { emailOrUsername, password } = inputs;
    try {
      const loginIdentifier = emailOrUsername.includes("@")
        ? "email"
        : "username";
      console.log(
        `Attempting login with ${loginIdentifier}: ${emailOrUsername}`
      );
      await handleLogin(emailOrUsername, password);
    } catch (error) {
      console.log(error.message);
    }
  };

  return (
    <LoginCardStyle>
      <h2>Log In</h2>
      <div className="card">
        <form className="input-fields">
          <StyledInput
            type="text"
            placeholder="E-Mail or Username"
            onChange={handleChange}
            name="emailOrUsername"
            value={inputs.emailOrUsername}
            required
          />
          <StyledPasswordInput
            type="password"
            placeholder="Password"
            onChange={handleChange}
            onKeyPress={handlePasswordKeyPress}
            name="password"
            value={inputs.password}
            required
          />
        </form>
        <Button
          bg="#2db4a0"
          padding="10px 20px"
          borderradius="5px"
          color="#ffffff"
          hoverBg="#009782"
          disabledColor="#c3eddf"
          name="Log In"
          onClick={handleSubmit}
          disabled={!allFieldsFilled}
        />
        <div>
          Don't have an account?{" "}
          <button
            className="authAtom-btn"
            onClick={() => setAuthScreen("signup")}
          >
            Sign up
          </button>
        </div>
      </div>
    </LoginCardStyle>
  );
}

const LoginCardStyle = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background-color: #f0f0f0;

  .card {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    width: 90%;
    max-width: 600px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
  }

  h2 {
    margin-bottom: 15px;
    color: #333;
    font-size: 24px;
  }

  .input-fields {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
  }

  .authAtom-btn {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    color: #2db4a0;
    cursor: pointer;
  }

  .authAtom-btn:hover {
    color: #009782;
  }

  .authAtom-btn:focus {
    outline: none;
  }

  @media (max-width: 768px) {
    .card {
      padding: 15px;
    }
  }

  @media (max-width: 480px) {
    .card {
      padding: 10px;
    }
  }
`;

const inputfieldStyles = `
  width: calc(100% - 40px);
  padding: 10px;
  margin-bottom: 5px;
  border: 2px solid #ccc;
  border-radius: 5px;
  transition: border-color 0.3s;
  
  &:focus,
  &:hover {
    border-color: #2db4a0;
    outline: none;
  }
  
  &:focus-visible {
    border-color: #2db4a0;
    outline: none;
  }
`;

const StyledInput = styled(Input)`
  ${inputfieldStyles}

  @media (max-width: 768px) {
    width: calc(100% - 30px);
  }

  @media (max-width: 480px) {
    width: calc(100% - 20px);
    padding: 8px;
  }
`;

const StyledPasswordInput = styled(Input.Password)`
  ${inputfieldStyles}

  @media (max-width: 768px) {
    width: calc(100% - 30px);
  }

  @media (max-width: 480px) {
    width: calc(100% - 20px);
    padding: 8px;
  }
`;

export default LoginCard;
