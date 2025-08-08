import React from "react";
import ScrollToTop from "../components/scroll-to-top";
import SEO from "../components/seo";
import PageTitleContainerTwo from "../containers/global/page-title-two";
import VideoGalleryContainer from "../containers/video-gallery";
import Footer from "../layouts/footer";
import Header from "../layouts/header/index";
import Layout from "../layouts/index";

const VideoGallery = () => {
    return (
        <React.Fragment>
            <Layout>
                <SEO title="Alexis || Video Gallery" />
                <div className="wrapper home-default-wrapper">
                    <Header classOption="hb-border" />
                    <div className="main-content">
                        <PageTitleContainerTwo
                            subTitle="Video Gallery"
                            title="Write &amp; Share"
                        />
                        <VideoGalleryContainer />
                    </div>
                    <Footer />
                    <ScrollToTop />
                </div>
            </Layout>
        </React.Fragment>
    );
};

export default VideoGallery;
