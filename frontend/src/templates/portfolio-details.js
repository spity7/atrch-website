import PropTypes from "prop-types";
import React from "react";
import ScrollToTop from "../components/scroll-to-top";
import SEO from "../components/seo";
import PortfolioDetailsContainer from "../containers/portfolio-details";
import PortfolioData from "../data/portfolio.json";
import Footer from "../layouts/footer";
import Header from "../layouts/header/index";
import Layout from "../layouts/index";

const PortfolioDetails = ({
    match: {
        params: { id },
    },
}) => {
    const projectId = parseInt(id, 10);
    const data = PortfolioData.filter((project) => project.id === projectId);
    return (
        <React.Fragment>
            <Layout>
                <SEO title="Alexis || Portfolio Details" />
                <div className="wrapper home-default-wrapper">
                    <Header classOption="hb-border" />
                    <div className="main-content">
                        <PortfolioDetailsContainer data={data[0]} />
                    </div>
                    <Footer />
                    <ScrollToTop />
                </div>
            </Layout>
        </React.Fragment>
    );
};

PortfolioDetails.propTypes = {
    match: PropTypes.shape({
        params: PropTypes.shape({
            id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
        }),
    }),
};

export default PortfolioDetails;
