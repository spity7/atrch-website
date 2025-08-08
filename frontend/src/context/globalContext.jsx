import React, { createContext, useContext, useState, useCallback } from "react";
import axios from "axios";
import { useAtom } from "jotai";
import userAtom from "@/atoms/userAtom";
import useShowModal from "@/hooks/useShowModal";

axios.defaults.withCredentials = true;
// const BASE_URL = "https://api.milaresidence.com/api/v1/";
const BASE_URL = "https://api.domain/api/v1/";

const GlobalContext = createContext();

export const GlobalProvider = ({ children }) => {
    const showModal = useShowModal();
    const [, setUser] = useAtom(userAtom);

    const [allEmployees, setAllEmployees] = useState([]);
    const [totalEmployees, setTotalEmployees] = useState(0);
    const [currentPage, setCurrentPage] = useState(1);
    const [pageSize, setPageSize] = useState(6);
    const [roles, setRoles] = useState([]);
    const [searchTerm, setSearchTerm] = useState("");
    const [selectedRoles, setSelectedRoles] = useState([]);

    const [allProperties, setAllProperties] = useState([]);
    const [totalProperties, setTotalProperties] = useState(0);
    const [types, setTypes] = useState([]);
    const [selectedTypes, setSelectedTypes] = useState([]);

    const handleSignup = async (
        firstname,
        lastname,
        username,
        email,
        password,
        role
    ) => {
        // Simple email validation regex
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showModal("Error", "Please enter a valid email address.", "error");
            return; // Don't proceed with signup if email is invalid
        }

        try {
            const res = await axios.post(`${BASE_URL}signup`, {
                firstname,
                lastname,
                username,
                email,
                password,
                role,
            });

            const data = await res.data;

            if (data.error) {
                showModal("Error", data.error, "error");
                return;
            }

            // Store a message or status in localStorage to show to the user
            localStorage.setItem(
                "signup-status",
                JSON.stringify({
                    message:
                        "Signup successful! Please check your email to verify your account.",
                })
            );

            window.location.href = "/verify-email";
        } catch (error) {
            if (error.response && error.response.status === 400) {
                showModal("Error", error.response.data.error, "error");
            } else {
                showModal(
                    "Error",
                    "An error occurred. Please try again.",
                    "error"
                );
            }
        }
    };

    const handleLogin = async (emailOrUsername, password) => {
        try {
            const res = await axios.post(`${BASE_URL}login`, {
                emailOrUsername,
                password,
            });

            const data = res.data;
            console.log("data", data);
            if (res.status === 200) {
                // check if user is verified
                if (!data.isVerified) {
                    showModal(
                        "Error",
                        "Please verify your email before logging in.",
                        "error"
                    );
                    return;
                }
                // check if there is signup-status in localstorage and clear
                if (localStorage.getItem("signup-status")) {
                    localStorage.removeItem("signup-status");
                }
                localStorage.setItem("user-app", JSON.stringify(data));
                setUser(data);
            } else {
                showModal(
                    "Error",
                    data.error || "Unknown error occurred",
                    "error"
                );
            }

            window.location.href = "/";
        } catch (error) {
            // Netzwerkfehler oder andere Fehler
            if (error.response) {
                const status = error.response.status;
                if (status === 401) {
                    showModal(
                        "Error",
                        "Unauthorized. Please log in again.",
                        "error"
                    );
                } else if (status === 400) {
                    showModal("Error", error.response.data.error, "error");
                } else {
                    showModal("Error", `HTTP Error ${status}`, "error");
                }
            } else if (error.request) {
                showModal("Error", "No response from server", "error");
            } else {
                showModal(
                    "Error",
                    "An error occurred. Please try again.",
                    "error"
                );
            }
            console.error("Login error:", error.message);
        }
    };

    const handleLogout = async () => {
        try {
            const res = await axios.post(`${BASE_URL}logout`);
            const data = res.data;

            if (data.error) {
                showModal("Error", data.error, "error");
                return;
            }

            localStorage.removeItem("user-app");
            setUser(null);
            window.location.href = "/";
        } catch (error) {
            console.error("Error while logging out:", error.message);
            showModal("Error", error.message, "error");
        }
    };

    const getAllProperties = useCallback(
        async (page = 1, limit = 6, project = "", search = "", types = []) => {
            try {
                const response = await axios.get(
                    `${BASE_URL}get-all-properties`,
                    {
                        params: {
                            search,
                            page,
                            limit,
                            project,
                            types,
                        },
                    }
                );
                return response.data;
            } catch (error) {
                console.error("Error fetching properties:", error);
                return null;
            }
        },
        []
    );

    const fetchTypes = useCallback(async (project = "") => {
        try {
            const response = await axios.get(`${BASE_URL}types`, {
                params: { project },
            });
            return response.data;
        } catch (error) {
            console.error("Error fetching types:", error);
            return [];
        }
    }, []);

    const handleUpdateProperty = async (propertyId, values) => {
        try {
            const response = await axios.put(
                `${BASE_URL}update-property/${propertyId}`,
                values
            );
            return response;
        } catch (error) {
            throw error;
        }
    };

    const fetchPropertyByPropertyId = useCallback(async (propertyId) => {
        try {
            const response = await axios.get(
                `${BASE_URL}property/${propertyId}`
            );
            return response.data;
        } catch (error) {
            console.error("Error fetching property:", error);
            throw error;
        }
    }, []);

    const contactUs = async (formData) => {
        try {
            const response = await axios.post(
                `${BASE_URL}contact-us`,
                formData
            );
            return response.data;
        } catch (error) {
            console.error("Error sending contact form:", error);
            throw error;
        }
    };

    return (
        <GlobalContext.Provider
            value={{
                handleSignup,
                handleLogin,
                handleLogout,
                getAllProperties,
                allProperties,
                totalProperties,
                currentPage,
                setCurrentPage,
                pageSize,
                setPageSize,
                fetchTypes,
                types,
                setTypes,
                searchTerm,
                setSearchTerm,
                selectedTypes,
                setSelectedTypes,
                fetchPropertyByPropertyId,
                handleUpdateProperty,
                contactUs,
            }}
        >
            {children}
        </GlobalContext.Provider>
    );
};

export const useGlobalContext = () => {
    return useContext(GlobalContext);
};
