import React, { useEffect, useState } from "react";
import styled from "styled-components";
import { useAtom } from "jotai";
import { Input } from "antd";
import { useGlobalContext } from "@/context/globalContext";
import authScreenAtom from "@/atoms/authAtom";
import Button from "@/components/Button";

function SignupCard() {
  const [inputs, setInputs] = useState({
    firstname: "",
    lastname: "",
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
    role: "User",
  });

  const [passwordCriteria, setPasswordCriteria] = useState({
    length: false,
    upperCase: false,
    lowerCase: false,
    number: false,
    specialChar: false,
  });

  const { handleSignup } = useGlobalContext();
  const [passwordMatch, setPasswordMatch] = useState(false);
  const [validPassword, setValidPassword] = useState(false);
  const [allFieldsFilled, setAllFieldsFilled] = useState(false);
  const [, setAuthScreen] = useAtom(authScreenAtom);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setInputs((prevInputs) => ({
      ...prevInputs,
      [name]: value,
    }));

    if (name === "password") {
      validatePassword(value);
    }
  };

  const validatePassword = (password) => {
    const regexUpperCase = /[A-Z]/;
    const regexLowerCase = /[a-z]/;
    const regexNumber = /[0-9]/;
    const regexSpecialChar = /[!@#$%^&*(),.?":{}|<>]/;

    const length = password.length >= 8;
    const upperCase = regexUpperCase.test(password);
    const lowerCase = regexLowerCase.test(password);
    const number = regexNumber.test(password);
    const specialChar = regexSpecialChar.test(password);

    setPasswordCriteria({
      length,
      upperCase,
      lowerCase,
      number,
      specialChar,
    });

    setValidPassword(length && upperCase && lowerCase && number && specialChar);
  };

  useEffect(() => {
    setPasswordMatch(
      inputs.password === inputs.confirmPassword ||
        inputs.confirmPassword === ""
    );
  }, [inputs.password, inputs.confirmPassword]);

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
    try {
      await handleSignup(
        inputs.firstname,
        inputs.lastname,
        inputs.username,
        inputs.email,
        inputs.password,
        inputs.role
      );
    } catch (error) {
      console.log(error.message);
    }
  };

  return (
    <SignupCardStyle>
      <h2>Signup</h2>
      <div className="card">
        <form className="input-fields">
          <StyledInput
            type="text"
            placeholder="First Name"
            onChange={handleChange}
            name="firstname"
            value={inputs.firstname}
            required
          />
          <StyledInput
            type="text"
            placeholder="Last Name"
            onChange={handleChange}
            name="lastname"
            value={inputs.lastname}
            required
          />
          <StyledInput
            type="text"
            placeholder="Username"
            onChange={handleChange}
            name="username"
            value={inputs.username}
            required
          />
          <StyledInput
            type="email"
            placeholder="E-Mail"
            onChange={handleChange}
            name="email"
            value={inputs.email}
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
          <PasswordCriteria>
            <Criteria>
              <input type="radio" readOnly checked={passwordCriteria.length} />
              <span>At least 8 characters</span>
            </Criteria>
            <Criteria>
              <input
                type="radio"
                readOnly
                checked={passwordCriteria.upperCase}
              />
              <span>At least one uppercase letter</span>
            </Criteria>
            <Criteria>
              <input
                type="radio"
                readOnly
                checked={passwordCriteria.lowerCase}
              />
              <span>At least one lowercase letter</span>
            </Criteria>
            <Criteria>
              <input type="radio" readOnly checked={passwordCriteria.number} />
              <span>At least one number</span>
            </Criteria>
            <Criteria>
              <input
                type="radio"
                readOnly
                checked={passwordCriteria.specialChar}
              />
              <span>At least one special character</span>
            </Criteria>
          </PasswordCriteria>
          <StyledPasswordInput
            type="password"
            placeholder="Confirm password"
            onChange={handleChange}
            onKeyPress={handlePasswordKeyPress}
            name="confirmPassword"
            value={inputs.confirmPassword}
            required
          />
          {!passwordMatch && (
            <ErrorMessage>Passwords do not match!</ErrorMessage>
          )}
        </form>
        <Button
          bg="#2db4a0"
          padding="10px 20px"
          borderradius="5px"
          color="#ffffff"
          hoverBg="#009782"
          disabledColor="#c3eddf"
          name="Sign Up"
          onClick={handleSubmit}
          disabled={!validPassword || !passwordMatch || !allFieldsFilled}
        />
        <div>
          Already a user?{" "}
          <button
            className="authAtom-btn"
            onClick={() => setAuthScreen("login")}
          >
            Log in
          </button>
        </div>
      </div>
    </SignupCardStyle>
  );
}

const SignupCardStyle = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background-color: #f8f9fa;

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

const PasswordCriteria = styled.div`
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  width: 90%;
  margin-bottom: 10px;
`;

const Criteria = styled.div`
  display: flex;
  align-items: center;
  margin-bottom: 5px;

  input {
    margin-right: 10px;
  }

  span {
    font-size: 14px;
  }
`;

const ErrorMessage = styled.p`
  color: red;
  font-size: 15px;
  margin-top: 5px;
`;

export default SignupCard;
