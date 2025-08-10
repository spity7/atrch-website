import authScreenAtom from "@/atoms/authAtom";
import { useAtom } from "jotai";
import LoginCard from "./LoginCard";
import SignupCard from "./SignupCard";

const AuthPage = () => {
  const [authScreenState] = useAtom(authScreenAtom);

  return <>{authScreenState === "login" ? <LoginCard /> : <SignupCard />}</>;
};

export default AuthPage;
