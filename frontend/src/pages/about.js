import React from "react";
import ScrollToTop from "../components/scroll-to-top";
import SEO from "../components/seo";
import AboutAward from "../containers/about/about-award";
import AboutService from "../containers/about/about-service/index.jsx";
import Blockquote from "../containers/about/blockquote";
import AboutGallery from "../containers/about/gallery";
import TeamContainer from "../containers/about/team";
import BrandContainer from "../containers/global/brand";
import PageTitleContainer from "../containers/global/page-title";
import Footer from "../layouts/footer";
import Header from "../layouts/header/index";
import Layout from "../layouts/index";

const AboutPage = () => {
    return (
        <React.Fragment>
            <Layout>
                <SEO title="Alexis || About" />
                <div className="wrapper about-page-wrapper">
                    <Header classOption="hb-border" />
                    <div className="main-content">
                        <PageTitleContainer />
                        <AboutService />
                        <TeamContainer />
                        <Blockquote />
                        {/* <AboutGallery /> */}
                        {/* <AboutAward /> */}
                        {/* <BrandContainer /> */}
                    </div>
                    <Footer />
                    <ScrollToTop />
                </div>
            </Layout>
        </React.Fragment>
    );
};

export default AboutPage;
