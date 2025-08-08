import PropTypes from "prop-types";
import React, { useState } from "react";
import ModalVideo from "react-modal-video";

const PopupVideo = ({ data }) => {
    const [isOpen, setOpen] = useState(false);
    return (
        <div className="single-portfolio">
            {data?.type === "image" && (
                <div className="thumbnail">
                    <div className="overlay">
                        <img
                            src={process.env.PUBLIC_URL + data.homeImage}
                            alt="portfolio"
                        />
                    </div>
                    <div className="play-btn">
                        <button onClick={() => setOpen(true)}>
                            <i className="icofont-play-alt-2"></i>
                        </button>
                    </div>
                </div>
            )}
            {data?.type === "video" && (
                <iframe
                    className="iframe-video"
                    src={data.videoUrl}
                    title="YouTube video player"
                ></iframe>
            )}
            <ModalVideo
                channel="youtube"
                autoplay
                isOpen={isOpen}
                videoId="KzhSW1Ztq1w"
                onClose={() => setOpen(false)}
            />
        </div>
    );
};

PopupVideo.propTypes = {
    data: PropTypes.object,
};

export default PopupVideo;
