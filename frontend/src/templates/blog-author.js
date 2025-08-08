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

const BlogAuthor = ({
    match: {
        params: { author },
    },
}) => {
    const data = BlogData.filter((blog) => slugify(blog.author) === author);
    const authorTitle = data[0].author;
    return (
        <React.Fragment>
            <Layout>
                <SEO title="Alexis || Blog Author" />
                <div className="wrapper home-default-wrapper">
                    <Header classOption="hb-border" />
                    <div className="main-content">
                        <PageTitleContainerTwo
                            subTitle="Author"
                            title={authorTitle}
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

BlogAuthor.propTypes = {
    match: PropTypes.shape({
        params: PropTypes.shape({
            author: PropTypes.string,
        }),
    }),
};

export default BlogAuthor;
