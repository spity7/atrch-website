import PropTypes from "prop-types";
import React from "react";
import ScrollToTop from "../components/scroll-to-top";
import SEO from "../components/seo";
import BlogItemContainer from "../containers/blog/blog-item";
import PageTitleContainerTwo from "../containers/global/page-title-two";
import BlogData from "../data/blog.json";
import Footer from "../layouts/footer";
import Header from "../layouts/header/index";
import Layout from "../layouts/index";
import { slugify } from "../utils";

const BlogCategory = ({
    match: {
        params: { slug },
    },
}) => {
    const data = BlogData.map((blog) => {
        return {
            ...blog,
            categories: blog.categories.filter((cat) => slugify(cat) === slug),
        };
    }).filter((blog) => blog.categories.length > 0);
    const categoryTitle = data[0].categories[0];
    return (
        <React.Fragment>
            <Layout>
                <SEO title="Alexis || Blog Category" />
                <div className="wrapper home-default-wrapper">
                    <Header classOption="hb-border" />
                    <div className="main-content">
                        <PageTitleContainerTwo
                            subTitle="Category"
                            title={categoryTitle}
                        />
                        <BlogItemContainer data={data} />
                    </div>
                    <Footer />
                    <ScrollToTop />
                </div>
            </Layout>
        </React.Fragment>
    );
};

BlogCategory.propTypes = {
    match: PropTypes.shape({
        params: PropTypes.shape({
            slug: PropTypes.string,
        }),
    }),
};

export default BlogCategory;
