import PropTypes from "prop-types";
import { slugify } from "../../../utils";

const BlogFilter = ({ categories }) => {
    return (
        <div className="blog-filter-menu">
            <button className="active is-checked" data-filter="*">
                All
            </button>
            {categories?.map((cat, idx) => (
                <button key={idx} data-filter={`.${slugify(cat)}`}>
                    <span className="filter-text">{cat}</span>
                </button>
            ))}
        </div>
    );
};

BlogFilter.propTypes = {
    categories: PropTypes.array,
};

export default BlogFilter;
