import React from "react";
import Qute from "../../../components/qute/index";
import HomeData from "../../../data/home.json";

const QuteContainer = () => {
    return (
        <div className="home-slider-area slider-photographer">
            <div className="container">
                <div className="row">
                    <div className="col-md-12 col-lg-11 col-xl-10 m-auto">
                        <Qute data={HomeData[1]} />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default QuteContainer;
