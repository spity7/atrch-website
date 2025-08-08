import PropTypes from "prop-types";
import { Link } from "react-router-dom";

const Logo = ({ image }) => {
    return (
        <Link to={process.env.PUBLIC_URL + "/"}>
            <img
                className="logo-main"
                src={process.env.PUBLIC_URL + image}
                alt="Logo"
            />
            <img
                className="logo-light"
                src={process.env.PUBLIC_URL + image}
                alt="Logo"
            />
        </Link>
    );
};

Logo.propTypes = {
    image: PropTypes.string,
};

export default Logo;
