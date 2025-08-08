import PropTypes from "prop-types";
import { Link } from "react-router-dom";

const Brand = ({ data }) => {
    return (
        <div className="brand-logo-item">
            <Link to={process.env.PUBLIC_URL + "/"}>
                <img
                    src={process.env.PUBLIC_URL + data.image}
                    alt="Brand-Logo"
                />
            </Link>
        </div>
    );
};

Brand.propTypes = {
    data: PropTypes.object,
};

export default Brand;
