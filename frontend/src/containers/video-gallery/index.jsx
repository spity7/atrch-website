import React from "react";
import PopupVideo from "../../components/popup-video";
import PortfolioData from "../../data/portfolio.json";
import useMasonry from "../../hooks/use-masonry";

const VideoGalleryContainer = () => {
    const { categories } = useMasonry(PortfolioData, ".portfolio-list");
    return (
        <div className="portfolio-area portfolio-default-area">
            <div className="container-fluid">
                <div className="row row-cols-1 row-cols-sm-2 row-cols-lg-3 row-cols-xl-4 portfolio-list mb-n30">
                    <div className="col"></div>
                    {PortfolioData &&
                        PortfolioData.map((portfolio) => (
                            <div
                                key={portfolio.id}
                                className={`col masonry-grid mb-30`}
                            >
                                <PopupVideo data={portfolio} />
                            </div>
                        ))}
                </div>
            </div>
        </div>
    );
};

export default VideoGalleryContainer;
