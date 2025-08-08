import PropTypes from "prop-types";
import { slugify } from "../../../utils";

const PortfolioFilter = ({ categories }) => {
    return (
        <div className="messonry-button text-center mb-50">
            <button data-filter="*" className="is-checked">
                <span className="filter-text">All</span>
            </button>
            {categories?.map((cat, idx) => (
                <button key={idx} data-filter={`.${slugify(cat)}`}>
                    <span className="filter-text">{cat}</span>
                </button>
            ))}
        </div>
    );
};

PortfolioFilter.propTypes = {
    categories: PropTypes.array,
};

export default PortfolioFilter;
