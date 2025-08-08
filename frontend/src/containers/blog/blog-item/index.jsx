import PropTypes from "prop-types";
import BlogItem from "../../../components/blog/blog-item";
import useMasonry from "../../../hooks/use-masonry";

const BlogItemContainer = ({ data }) => {
    const { categories } = useMasonry(data, ".masonryGrid", ".masonry-item");
    return (
        <div className="blog-area blog-masonry-area">
            <div className="container">
                <div className="row masonryGrid post-items-style1">
                    <div className="col-sm-6 col-md-6 col-lg-4 resizer"></div>
                    {data &&
                        data.map((blog) => (
                            <div
                                key={blog.id}
                                className={`col-sm-6 col-md-6 col-lg-4 masonry-item`}
                            >
                                <BlogItem data={blog} />
                            </div>
                        ))}
                </div>
                <div className="row">
                    <div className="col-lg-12 text-center">
                        <button className="btn-more">...Load More...</button>
                    </div>
                </div>
            </div>
        </div>
    );
};

BlogItemContainer.propTypes = {
    data: PropTypes.array,
};

export default BlogItemContainer;
