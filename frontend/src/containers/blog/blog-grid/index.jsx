import React from "react";
import BlogFilter from "../../../components/blog/blog-filter";
import BlogItem from "../../../components/blog/blog-item";
import BlogData from "../../../data/blog.json";
import useMasonry from "../../../hooks/use-masonry";
import { slugify } from "../../../utils";

const BlogContainer = () => {
    const { categories } = useMasonry(
        BlogData,
        ".masonryGrid",
        ".masonry-item",
        ".blog-filter-menu",
        ".blog-filter-menu button"
    );
    return (
        <div className="blog-area blog-masonry-area">
            <div className="container">
                <div className="row">
                    <div className="col-lg-12 text-center">
                        <BlogFilter categories={categories} />
                    </div>
                </div>
                <div className="row masonryGrid post-items-style1">
                    <div className="col-sm-6 col-md-6 col-lg-4 resizer"></div>
                    {BlogData &&
                        BlogData.map((blog) => (
                            <div
                                key={blog.id}
                                className={`col-sm-6 col-md-6 col-lg-4 masonry-item ${blog.categories
                                    .map((cat) => slugify(cat))
                                    .join(" ")}`}
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

export default BlogContainer;
