import React from "react";
import ScrollToTop from "../components/scroll-to-top";
import SEO from "../components/seo";
import BlogContainer from "../containers/blog/blog-grid";
import PageTitleContainerTwo from "../containers/global/page-title-two";
import Footer from "../layouts/footer";
import Header from "../layouts/header/index";
import Layout from "../layouts/index";

const Blog = () => {
    return (
        <React.Fragment>
            <Layout>
                <SEO title="Alexis || Blog" />
                <div className="wrapper home-default-wrapper">
                    <Header classOption="hb-border" />
                    <div className="main-content">
                        <PageTitleContainerTwo
                            subTitle="Our Blog"
                            title="Write &amp; Share"
                        />
                        <BlogContainer />
                    </div>
                    <Footer />
                    <ScrollToTop />
                </div>
            </Layout>
        </React.Fragment>
    );
};

export default Blog;
