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

const BlogDate = ({
    match: {
        params: { date },
    },
}) => {
    const data = BlogData.filter((blog) => slugify(blog.date) === date);
    const dateTitle = data[0].date;
    return (
        <React.Fragment>
            <Layout>
                <SEO title="Alexis || Blog Date" />
                <div className="wrapper home-default-wrapper">
                    <Header classOption="hb-border" />
                    <div className="main-content">
                        <PageTitleContainerTwo
                            subTitle="Date"
                            title={dateTitle}
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

BlogDate.propTypes = {
    match: PropTypes.shape({
        params: PropTypes.shape({
            date: PropTypes.string,
        }),
    }),
};

export default BlogDate;
